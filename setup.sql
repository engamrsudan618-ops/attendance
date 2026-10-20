-- =====================================================
--  إعداد قاعدة بيانات "حضور المحاضرات" - شغّله مرة واحدة
--  Supabase > SQL Editor > الصق > Run
-- =====================================================

-- ---------- الجداول ----------
create table if not exists public.subjects(
  id serial primary key,
  name text not null
);

create table if not exists public.students(
  id int primary key,
  ref text,
  name text not null,
  code_hash text,
  user_id uuid unique references auth.users(id) on delete set null,
  device text,
  locked boolean not null default false,
  fails int not null default 0
);

create table if not exists public.staff(
  user_id uuid primary key references auth.users(id) on delete cascade
);

create table if not exists public.staff_codes(
  code_hash text primary key,
  used_by uuid,
  used_at timestamptz
);

create table if not exists public.staff_fails(
  user_id uuid primary key,
  tries int not null default 0
);

create table if not exists public.lectures(
  id bigserial primary key,
  subject_id int not null references public.subjects(id) on delete cascade,
  n int not null,
  opened_by uuid,
  opened_at timestamptz not null default now(),
  closes_at timestamptz not null,
  is_open boolean not null default true,
  use_gps boolean not null default false,
  use_net boolean not null default false,
  lat double precision,
  lon double precision,
  acc double precision,
  radius int not null default 100,
  net_ip text
);

create table if not exists public.lecture_codes(
  lecture_id bigint not null references public.lectures(id) on delete cascade,
  student_id int not null references public.students(id) on delete cascade,
  code text not null,
  primary key(lecture_id, student_id),
  unique(lecture_id, code)
);

create table if not exists public.attendance(
  lecture_id bigint not null references public.lectures(id) on delete cascade,
  student_id int not null references public.students(id) on delete cascade,
  at timestamptz not null default now(),
  manual boolean not null default false,
  primary key(lecture_id, student_id)
);

create table if not exists public.alerts(
  id bigserial primary key,
  lecture_id bigint not null references public.lectures(id) on delete cascade,
  student_id int not null references public.students(id) on delete cascade,
  reason text not null,
  typed text,
  at timestamptz not null default now()
);

-- ---------- الحماية: لا وصول مباشر للجداول، كل شيء عبر الدوال ----------
alter table public.subjects enable row level security;
alter table public.students enable row level security;
alter table public.staff enable row level security;
alter table public.staff_codes enable row level security;
alter table public.staff_fails enable row level security;
alter table public.lectures enable row level security;
alter table public.lecture_codes enable row level security;
alter table public.attendance enable row level security;
alter table public.alerts enable row level security;

revoke all on public.subjects, public.students, public.staff, public.staff_codes,
  public.staff_fails, public.lectures, public.lecture_codes, public.attendance,
  public.alerts from anon, authenticated;

grant select on public.subjects to authenticated;

do $$
begin
  if not exists (select 1 from pg_policies where schemaname='public' and tablename='subjects' and policyname='subjects_read') then
    create policy subjects_read on public.subjects for select to authenticated using (true);
  end if;
end $$;

-- ---------- دوال مساعدة ----------
create or replace function public.rand_code(len int) returns text
language plpgsql volatile as $$
declare
  a constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  r text := '';
  i int;
begin
  for i in 1..len loop
    r := r || substr(a, (get_byte(decode(replace(gen_random_uuid()::text,'-',''),'hex'),0) % 32) + 1, 1);
  end loop;
  return r;
end $$;

create or replace function public.norm_code(t text) returns text
language sql immutable as $$
  select regexp_replace(upper(coalesce(t,'')), '[^A-Z0-9]', '', 'g')
$$;

create or replace function public.code_hash(sid int, t text) returns text
language sql immutable as $$
  select encode(sha256(convert_to(sid::text || ':' || public.norm_code(t), 'UTF8')), 'hex')
$$;

create or replace function public.client_ip() returns text
language plpgsql stable as $$
declare h text;
begin
  h := nullif(current_setting('request.headers', true), '');
  if h is null then return null; end if;
  return nullif(trim(split_part(coalesce(h::json->>'x-forwarded-for', h::json->>'cf-connecting-ip', ''), ',', 1)), '');
exception when others then
  return null;
end $$;

create or replace function public.is_staff() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.staff where user_id = auth.uid())
$$;

-- ---------- الطالب ----------
create or replace function public.me(p_device text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare s public.students;
begin
  select * into s from public.students where user_id = auth.uid();
  if not found then return null; end if;
  return jsonb_build_object('ok', (s.device is not null and s.device = p_device), 'name', s.name);
end $$;

create or replace function public.list_students() returns table(id int, name text)
language sql stable security definer set search_path = public as $$
  select s.id, s.name from public.students s
  where s.user_id is null and auth.uid() is not null
  order by s.id
$$;

create or replace function public.activate(p_student int, p_code text, p_device text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare s public.students; uid uuid := auth.uid();
begin
  if uid is null then
    return jsonb_build_object('ok', false, 'msg', 'سجّل الدخول أولًا');
  end if;
  if exists(select 1 from public.students where user_id = uid) then
    return jsonb_build_object('ok', true, 'msg', 'حسابك مفعّل بالفعل');
  end if;
  if p_device is null or length(p_device) < 8 then
    return jsonb_build_object('ok', false, 'msg', 'تعذر التعرف على الجهاز');
  end if;
  select * into s from public.students where id = p_student for update;
  if not found or s.user_id is not null then
    return jsonb_build_object('ok', false, 'msg', 'هذا الاسم غير متاح للتفعيل');
  end if;
  if s.locked then
    return jsonb_build_object('ok', false, 'msg', 'التفعيل مقفول بعد محاولات خاطئة. كلّم الدكتور');
  end if;
  if s.code_hash is null then
    return jsonb_build_object('ok', false, 'msg', 'لا يوجد كود تفعيل لهذا الاسم. اطلب كودًا من الدكتور');
  end if;
  if s.code_hash <> public.code_hash(s.id, p_code) then
    update public.students set fails = fails + 1, locked = (fails + 1 >= 5) where id = s.id;
    return jsonb_build_object('ok', false, 'msg', 'كود التفعيل غير صحيح');
  end if;
  update public.students set user_id = uid, device = p_device, code_hash = null, fails = 0 where id = s.id;
  return jsonb_build_object('ok', true, 'msg', 'تم التفعيل');
end $$;

create or replace function public.mark_attendance(
  p_code text, p_lat double precision, p_lon double precision, p_acc double precision, p_device text
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  s public.students;
  lec public.lectures;
  oth record;
  v_code text := btrim(coalesce(p_code, ''));
  d double precision;
  tol double precision;
begin
  select * into s from public.students where user_id = auth.uid() for update;
  if not found then
    return jsonb_build_object('ok', false, 'msg', 'حسابك غير مفعّل بعد');
  end if;
  if s.device is distinct from p_device then
    return jsonb_build_object('ok', false, 'msg', 'هذا الحساب مربوط بجهاز آخر');
  end if;
  if s.locked then
    return jsonb_build_object('ok', false, 'msg', 'حسابك مقفول بعد محاولات خاطئة كثيرة. كلّم الدكتور لفتح القفل');
  end if;

  select l.* into lec
  from public.lectures l
  join public.lecture_codes c on c.lecture_id = l.id
  where c.student_id = s.id and c.code = v_code
  order by l.id desc limit 1;

  if found then
    if not (lec.is_open and now() < lec.closes_at) then
      return jsonb_build_object('ok', false, 'msg', 'انتهت مدة التسجيل لهذه المحاضرة');
    end if;
    if exists(select 1 from public.attendance a where a.lecture_id = lec.id and a.student_id = s.id) then
      return jsonb_build_object('ok', true, 'msg', 'تم تسجيل حضورك مسبقًا');
    end if;

    if lec.use_gps then
      if p_lat is null or p_lon is null then
        return jsonb_build_object('ok', false, 'msg', 'تعذر قراءة موقعك. اسمح للمتصفح بالوصول للموقع وفعّل GPS ثم أعد المحاولة');
      end if;
      d := 2 * 6371000 * asin(least(1, sqrt(
            power(sin(radians(p_lat - lec.lat) / 2), 2) +
            cos(radians(lec.lat)) * cos(radians(p_lat)) * power(sin(radians(p_lon - lec.lon) / 2), 2))));
      tol := lec.radius + least(coalesce(p_acc, 0), 50) + least(coalesce(lec.acc, 0), 30);
      if d > tol then
        insert into public.alerts(lecture_id, student_id, reason, typed)
        values (lec.id, s.id, 'خارج نطاق القاعة', round(d)::text || ' م');
        return jsonb_build_object('ok', false, 'msg', 'أنت خارج نطاق القاعة');
      end if;
    end if;

    if lec.use_net and public.client_ip() is distinct from lec.net_ip then
      insert into public.alerts(lecture_id, student_id, reason, typed)
      values (lec.id, s.id, 'من خارج شبكة القاعة', null);
      return jsonb_build_object('ok', false, 'msg', 'سجّل من شبكة القاعة فقط');
    end if;

    insert into public.attendance(lecture_id, student_id, manual) values (lec.id, s.id, false);
    update public.students set fails = 0 where id = s.id;
    return jsonb_build_object('ok', true, 'msg', 'تم تسجيل حضورك ✓');
  end if;

  select c.lecture_id, c.student_id into oth
  from public.lecture_codes c
  join public.lectures l on l.id = c.lecture_id
  where c.code = v_code and l.is_open and now() < l.closes_at
  limit 1;
  if found then
    insert into public.alerts(lecture_id, student_id, reason, typed)
    values (oth.lecture_id, s.id, 'كتب كود طالب آخر', v_code);
  end if;

  update public.students set fails = fails + 1, locked = (fails + 1 >= 5) where id = s.id;
  return jsonb_build_object('ok', false, 'msg', 'الكود غير صحيح');
end $$;

create or replace function public.my_attendance() returns table(subject text, attended int, total int)
language sql stable security definer set search_path = public as $$
  select sub.name,
    (select count(*)::int from public.attendance a join public.lectures l on l.id = a.lecture_id
      where l.subject_id = sub.id and a.student_id = st.id),
    (select count(*)::int from public.lectures l2 where l2.subject_id = sub.id)
  from public.subjects sub
  cross join (select id from public.students where user_id = auth.uid()) st
  order by sub.id
$$;

-- ---------- الدكتور ----------
create or replace function public.become_staff(p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); h text; v_tries int;
begin
  if uid is null then
    return jsonb_build_object('ok', false, 'msg', 'سجّل الدخول أولًا');
  end if;
  if exists(select 1 from public.staff where user_id = uid) then
    return jsonb_build_object('ok', true, 'msg', 'حسابك مفعّل');
  end if;
  select coalesce(max(f.tries), 0) into v_tries from public.staff_fails f where f.user_id = uid;
  if v_tries >= 10 then
    return jsonb_build_object('ok', false, 'msg', 'تم إيقاف المحاولات لهذا الحساب');
  end if;
  h := encode(sha256(convert_to(public.norm_code(p_code), 'UTF8')), 'hex');
  update public.staff_codes set used_by = uid, used_at = now() where code_hash = h and used_by is null;
  if found then
    insert into public.staff(user_id) values (uid) on conflict do nothing;
    return jsonb_build_object('ok', true, 'msg', 'تم التفعيل');
  end if;
  insert into public.staff_fails(user_id, tries) values (uid, 1)
  on conflict (user_id) do update set tries = public.staff_fails.tries + 1;
  return jsonb_build_object('ok', false, 'msg', 'كود الدكتور غير صحيح');
end $$;

create or replace function public.students_status() returns table(id int, name text, activated boolean, locked boolean)
language sql stable security definer set search_path = public as $$
  select s.id, s.name, (s.user_id is not null), s.locked
  from public.students s where public.is_staff() order by s.id
$$;

create or replace function public.generate_activation_pack(p_student int default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r record; c text; res jsonb := '[]'::jsonb;
begin
  if not public.is_staff() then raise exception 'غير مسموح'; end if;
  for r in
    select s.id, s.name from public.students s
    where s.user_id is null and (p_student is null or s.id = p_student)
    order by s.id
  loop
    c := public.rand_code(4) || '-' || public.rand_code(4);
    update public.students set code_hash = public.code_hash(r.id, c), fails = 0, locked = false where id = r.id;
    res := res || jsonb_build_object('nm', r.name, 'cd', c);
  end loop;
  return res;
end $$;

create or replace function public.reset_device(p_student int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_staff() then raise exception 'غير مسموح'; end if;
  update public.students
  set user_id = null, device = null, code_hash = null, fails = 0, locked = false
  where id = p_student;
end $$;

create or replace function public.unlock_student(p_student int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_staff() then raise exception 'غير مسموح'; end if;
  update public.students set locked = false, fails = 0 where id = p_student;
end $$;

create or replace function public.open_lecture(
  p_subject int, p_window int, p_net boolean, p_gps boolean,
  p_lat double precision, p_lon double precision, p_acc double precision, p_radius int
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare lid bigint; nn int; r record; c text; ip text;
begin
  if not public.is_staff() then raise exception 'غير مسموح'; end if;
  if not exists(select 1 from public.subjects where id = p_subject) then
    raise exception 'المادة غير موجودة';
  end if;
  if p_gps and (p_lat is null or p_lon is null) then
    raise exception 'الموقع مطلوب لفتح الحضور بالـ GPS';
  end if;
  ip := public.client_ip();
  if p_net and ip is null then
    raise exception 'تعذر قراءة شبكتك';
  end if;

  update public.lectures set is_open = false, closes_at = least(closes_at, now())
  where opened_by = auth.uid() and is_open;

  select coalesce(max(l.n), 0) + 1 into nn from public.lectures l where l.subject_id = p_subject;

  insert into public.lectures(subject_id, n, opened_by, closes_at, use_gps, use_net, lat, lon, acc, radius, net_ip)
  values (p_subject, nn, auth.uid(),
          now() + make_interval(mins => greatest(1, least(coalesce(p_window, 15), 120))),
          coalesce(p_gps, false), coalesce(p_net, false), p_lat, p_lon, p_acc,
          greatest(20, least(coalesce(p_radius, 100), 1000)),
          case when p_net then ip else null end)
  returning id into lid;

  for r in select s.id from public.students s order by s.id loop
    loop
      c := lpad(((('x' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 7))::bit(28)::int) % 1000000)::text, 6, '0');
      exit when not exists(select 1 from public.lecture_codes lc where lc.lecture_id = lid and lc.code = c);
    end loop;
    insert into public.lecture_codes(lecture_id, student_id, code) values (lid, r.id, c);
  end loop;

  return jsonb_build_object('id', lid, 'n', nn);
end $$;

create or replace function public.close_lecture(p_lecture bigint) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_staff() then raise exception 'غير مسموح'; end if;
  update public.lectures set is_open = false, closes_at = least(closes_at, now()) where id = p_lecture;
end $$;

create or replace function public.lecture_sheet(p_lecture bigint)
returns table(sid int, nm text, cd text, present boolean, manual boolean)
language sql stable security definer set search_path = public as $$
  select s.id, s.name, lc.code, (a.student_id is not null), coalesce(a.manual, false)
  from public.lecture_codes lc
  join public.students s on s.id = lc.student_id
  left join public.attendance a on a.lecture_id = lc.lecture_id and a.student_id = lc.student_id
  where lc.lecture_id = p_lecture and public.is_staff()
  order by s.id
$$;

create or replace function public.lecture_alerts(p_lecture bigint)
returns table(nm text, reason text, typed text)
language sql stable security definer set search_path = public as $$
  select s.name, al.reason, al.typed
  from public.alerts al join public.students s on s.id = al.student_id
  where al.lecture_id = p_lecture and public.is_staff()
  order by al.at desc
$$;

create or replace function public.manual_mark(p_lecture bigint, p_student int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_staff() then raise exception 'غير مسموح'; end if;
  insert into public.attendance(lecture_id, student_id, manual) values (p_lecture, p_student, true)
  on conflict do nothing;
end $$;

create or replace function public.attendance_report(p_subject int default null)
returns table(nm text, subject text, attended int, total int)
language sql stable security definer set search_path = public as $$
  select st.name, sub.name,
    (select count(*)::int from public.attendance a join public.lectures l on l.id = a.lecture_id
      where l.subject_id = sub.id and a.student_id = st.id),
    (select count(*)::int from public.lectures l2 where l2.subject_id = sub.id)
  from public.students st
  cross join public.subjects sub
  where public.is_staff() and (p_subject is null or sub.id = p_subject)
  order by st.id, sub.id
$$;

-- ---------- الصلاحيات ----------
revoke all on all functions in schema public from public, anon, authenticated;

grant execute on function
  public.is_staff(),
  public.me(text),
  public.list_students(),
  public.activate(int, text, text),
  public.become_staff(text),
  public.generate_activation_pack(int),
  public.students_status(),
  public.reset_device(int),
  public.unlock_student(int),
  public.open_lecture(int, int, boolean, boolean, double precision, double precision, double precision, int),
  public.close_lecture(bigint),
  public.lecture_sheet(bigint),
  public.lecture_alerts(bigint),
  public.manual_mark(bigint, int),
  public.mark_attendance(text, double precision, double precision, double precision, text),
  public.my_attendance(),
  public.attendance_report(int)
to authenticated;

-- ---------- المواد (غيّر الأسماء لاحقًا من Table Editor) ----------
insert into public.subjects(name)
select v.x from (values ('المادة الأولى'), ('المادة الثانية'), ('المادة الثالثة')) as v(x)
where not exists (select 1 from public.subjects);

-- ---------- الطلاب (الأسماء + أكواد التفعيل مشفّرة، الأكواد الأصلية في ملف الإكسل) ----------
insert into public.students(id, ref, name, code_hash) values
  (1, 'AE-001', 'شادى محمد محمد الصياد', 'ddfd4af6a0ccddcb511bddd2c123a77497a496aa14d4a61b009622cedcfcd7af'),
  (2, 'AE-002', 'مصطفى محمد حمد الرفاعي', '9cf37a37a88080fe5d55dffd17256a0b922d148d6e563a6ab5e5dd574e7b6a77'),
  (3, 'AE-003', 'يوسف بهيج متولي بهيج', 'e324bd161f3b5043e5f51c1712a5a6c76451969ba64623290db45d9031c43fe7'),
  (4, 'AE-004', 'محمد عبدالرحمن عبده العشماوي', '5e19ed654ef1e10eb695bea113fd90a1fbb61b7d9ee6b9a9a994bd7e58950530'),
  (5, 'AE-005', 'معاذ اشرف علي راضي', '553329a45df4cd7f22b28c06578d7fc5eb01a31e2020273abe347f5cc6559572'),
  (6, 'AE-006', 'عبدالرحمن السعيد احمد عقاب', '639632c00ad1ca7e54f84ddf2087123c77ba2d4bcc15a7eb211ae801992697f8'),
  (7, 'AE-007', 'حنان محمد شعيب الصوالحي', 'ae6e25a3edeca5c5d273e637e98412c6daea04777c59af1184fe43a8ee5d86a8'),
  (8, 'AE-008', 'مهاب محمد احمد ابراهيم', '1480d9b9d87afef329e36977daa7045b5af1e3793af5294043cd8d76d62a42d8'),
  (9, 'AE-009', 'بلال خميس كامل حامد السيد الطحان', '77efce7f77cc86ef0c0f6c9d2e4ae584d852bbb9956750f19a69bc458053f4ba'),
  (10, 'AE-010', 'آيه إبراهيم أحمد حماد عيسى', 'ede9ab773856f652c4a3c17f61c57c8810917d63dc3f3995343091bf2d4e19d3'),
  (11, 'AE-011', 'نور الدين السعيد عبده عبد المولى', 'e2a5aecffacfb7c9dd31fa55e8b5aa5ea48171d15a9c9220d4052dcae10ab25c'),
  (12, 'AE-012', 'طه ياسر طه ابراهيم عجوره', 'a0ffdf4f2373a75856fe813453b5474e1b55123e33bf88335a84211a780026f8'),
  (13, 'AE-013', 'عمر مدحت محمد مصطفي', '7faa2aabf526e772eca15f587b33b497d6fcb1b4bd6174f5e379206a998b9ea0'),
  (14, 'AE-014', 'عبدالله تامر عبدالله', 'b6378063c830dfe50c8a9216ba0c2ce29ac8ad6910d300ca50ce0e142bbb851b'),
  (15, 'AE-015', 'محمود صالح صالح حسين', '4bb9418a38c16f0fc8e215c874b9d35a67114c512a2886682d4968f1a968ab97'),
  (16, 'AE-016', 'رفعت احمد خليفه الزبيدي', '04038fe9f19b40a604228eba27af8a33ce026a7d85b9d7286a4abb6a450c1f36'),
  (17, 'AE-017', 'آيه سعد غريب حسين', 'cec1dba77e7261e90029e3fa2823fba4943dfdf9b8e8ab90e0312d7e94d9977a'),
  (18, 'AE-018', 'علي محمد علي عروس', 'a70f8750863d999684b51e93812817b40adae437919c29e4d930973401d40298'),
  (19, 'AE-019', 'ندى محمد فتح الله الشاذلي', '9b7160a1dc0fd1ee886788fdb104950d53d212dfe38dfb95c4a7d8d15179d9e4'),
  (20, 'AE-020', 'نور محمد السيد احمد', 'd2b001f99c91c9aeeba259d2279a63a0f5257c7b6485ae7d391a745d49dfc9c3'),
  (21, 'AE-021', 'دعاء فرحان مختار محمد', 'e269a44cb5e766c438bcc75afec7c2bf27c52935f9c13e7c8991af70ff29f98e'),
  (22, 'AE-022', 'بسنت ناجح محمد عبدالعزيز', '0dd4d8116788215d5b1d09544152baaf3b05240c24d2620594ec669fb78c83cd'),
  (23, 'AE-023', 'عبدالله احمد بدوي نجم', 'ca9019a1f2c55f1ab8c37dc7f9f1b6e389c84bcf722a4b014002934848600cf9'),
  (24, 'AE-024', 'الاء محمود محمد الاسطى', 'f46f83d02cc1accf3a2ebf90f57cd3165b948099b22cb5c13b2eacdaf1be3c97'),
  (25, 'AE-025', 'طه حازم طه شاهين', '10dabe44323e64ee15541da548b25ae43b359ffaed37fe954ef4413b3a48d1ea'),
  (26, 'AE-026', 'ريمون بخيت فكري يعقوب', '0d23e2f3fd302746f7501285e69818d18b22364d8770c6d55c207d5f2333693b'),
  (27, 'AE-027', 'محمد رافت عثمان محروس ابو موسي', 'ed3966acf7f7ad41dd4fc6ae9171701f7a508b8cd78d2e059427c1e74171a8ad'),
  (28, 'AE-028', 'الحسين محمد رمضان عبدالعظيم', '183f35785ff034cd5d22c2cb64198cdf5f2c77e102295842d2f83abf2f0f4b9a'),
  (29, 'AE-029', 'ندى رمضان أحمد عبدالحميد', '4bc4758ffe416a33120a374a5fd6c4834178b32a6fe179ba7b081e0dab531643'),
  (30, 'AE-030', 'محمد جابر شحاته محمد', '59c2ab768b0ae5b7db5e53a8fe3313b32e66cc97e70cf7a6cb231dd88adaf740'),
  (31, 'AE-031', 'فارس رضا كامل محمد', '573c448f4c2916c04cfa6c97e112c52b32523da48ed8c97cf238490d1a22382c'),
  (32, 'AE-032', 'شهد ياسر السعيد جلاجل', '6fbd7a8e64272cb6047b32c16c1bfd7e654ab0033a74a762af99a5dda907d6d4'),
  (33, 'AE-033', 'زينب يوسف محمد عبدالونيس', '846d76feee9339dc9e0855dea2ba77e10a66e65163603d77c94ce0cdd216ea40'),
  (34, 'AE-034', 'حبيبه حسيني محمد حجازي', 'cf4de3c73691047d0a510c43bda3a5c0a634223c630d9782b0469d3b15cc4f62'),
  (35, 'AE-035', 'منه كارم صلاح حسين', '3260fef62fda37195edf0acecec5ea1255fbaa44f15e134d91f84d8646259338'),
  (36, 'AE-036', 'زياد محمد عبد المنعم خلف محمد', 'df744d7e1ac1b182ccf4c0ff2d67c41af29de2e3e27566317da0d3a6d630b6c2'),
  (37, 'AE-037', 'هاجر خالد فرج اسماعيل', '7e5398a70b13304dec201c66e45770c9c82e85ba1375369bbbc9a61222851f03'),
  (38, 'AE-038', 'عمر سعيد علي عثمان', '6ef1d2c926454c5fbfea55eb78f4a0873fea3d62bd1e6317909c443cf28d59bd'),
  (39, 'AE-039', 'بلال خيري سعد الزعويلي', '738ac24f3ecde3a07d2af36d1977d6f2528e730d6ef2cc0317e919cedc423680'),
  (40, 'AE-040', 'احمد محمد فتوح عرفه السيد', '75b55f9102cb468e8d61d9c9cb9b20f8d70d6dc5d7becb10348e6ae491ac172a'),
  (41, 'AE-041', 'عمرو عبدالمنعم محمد عبدالعزيز', 'a580e6efc5fce064e6fc342fc05a91a3c2f234a43702200c440e85d0ab8b2343'),
  (42, 'AE-042', 'حبيبه سلامه محمد سويد', 'e025d7bcc032e724b2b8e4430dbec1de729177c7acc6aa8bb28f85a10cce0edf'),
  (43, 'AE-043', 'محمد احمد بسيوني ناضر', '5be16b5edb89d1090b644656ab432fe9c80916262d6c84a326f86277b50a412d'),
  (44, 'AE-044', 'مريم عادل احمد المعداوي', '76f4ff98671ae3953d88742f54eb6f0c3e2c601a439747afc2556308ada4239d'),
  (45, 'AE-045', 'محمد علي محمد جمعة', 'b71cabfb96cfad9b03d45c08f37d4f2a1ae0464824dd1d88875358898a963eb1'),
  (46, 'AE-046', 'اسراء حسن محمد فليس', '88adbf6ef1556e8771181687fd60c907853dc4d9e7ea607ed075cba3ba64a985'),
  (47, 'AE-047', 'چنى محمود البرعي حبيشي', 'f447347fa3b0beec24c9f256acfe34fa896633b30bb9085270833319c0304113'),
  (48, 'AE-048', 'كيرلس عزت ناروز', '2739244bc0fa23becfb9859345fe3432d9e4468da10e4f059649e68cb954eb07'),
  (49, 'AE-049', 'سهير طلحه السيد احمد', 'c6fadd337008a0f0bbaa8bbc933b0d24e9c9eb097cdc71c3240e2d5f24232b6e'),
  (50, 'AE-050', 'احمد محمد شفيق احمد', 'cf306933d75e2bc7975f03a19aff7d1e1022b73caaec811211cdc54253c959ef'),
  (51, 'AE-051', 'منة الله علي السيد علي غراب', '33c50ae43c1c740cc04def3d156b7a293d6df9c29543635b0167fce56008423f'),
  (52, 'AE-052', 'يوسف احمد عبد الحميد محمد', '9327372a014a5010cecc929c15d76d0fb5c582d5bc0b59584bf9ad0b6fa5c1d1'),
  (53, 'AE-053', 'روان أحمد محمود الشاذلي', '927b0c7abd5281f35ad9ffed0c8f32041e299bd71c3994c60cb304141785023a'),
  (54, 'AE-054', 'عبدالوارث كرم عبدالوارث عشيبه', '835b6874a8cd16fc73abf4c04a2378f6577f3c67e935a3c7f5d695c37c8f30d6'),
  (55, 'AE-055', 'شهد عبدالمحسن بسيوني احمد', 'ca1f7e0604c179fa8a07ceb1173ef3530e271087302cddab8fa13522a4d51e80'),
  (56, 'AE-056', 'ابانوب منير عدلى زكى', 'e33af903ffe4863289ed4ff63dbb4a7474b575a3ef89fe5c18f9c0206455222a'),
  (57, 'AE-057', 'بسمله محمود محمد عبد المعطي البيومي', '01a83cb0decc971dafa3d7fd4ef6e4d7466321a2e9a3844d3c9e6a38e2d0051a'),
  (58, 'AE-058', 'ادهم ايمن محمد الحسيني', 'b3ea73efea7d8ef17a09738077b4a20ef66a54787d6e4aca50baeee6ca44353c'),
  (59, 'AE-059', 'عمر بسيوني رمضان عبدالرحمن', '2eeffedecbedcf6f623af6334932cbddd36cce0362416c04aff842ca5ced7a9c'),
  (60, 'AE-060', 'حمزة محمد محمود سليم', '09eabb7ba0d371e3ba90c6fd2da72c72b2ee3a6aa20ea57c61cc17f5aae1556a'),
  (61, 'AE-061', 'ندى رأفت غازي حامد', 'bf1373e5d4b116e25f357ef35acd438001f25a5ef9d39a05b8118bd2ed0c9dbc'),
  (62, 'AE-062', 'اضواء ابواليزيد حسن الاطروش', 'a832e5d5a00131b20c383d06b027bb195b90b51259471b25487b17fb510f2dc5'),
  (63, 'AE-063', 'يوسف اشرف سليمان', '810ac800626f02f0557fa66b8c99899a6fa06b2069851d1c35683b528da7013e'),
  (64, 'AE-064', 'احمد معروف فتح الله الحب', '37944c1876badbe04a8202479361bc6cdf2e899ea782cd498fc1fa45c294c950'),
  (65, 'AE-065', 'آلاء إيهاب عبدالستار محمد', '0b5c55d1ff296af00cdba327b6278d883c9246fd4672d21af0d6c576acfe8f74'),
  (66, 'AE-066', 'عطيه سعد مرشدي عطيه', '54495cd94570cf5351ee9ff05a7d982fedebcf27f8dd2e0a233fe1fabdfe2b85'),
  (67, 'AE-067', 'عمر رضا عيد مصطفى', '3b298d9944a256f1d46b87435a62022855b99cdae2620da78e9416ea94d55aa9'),
  (68, 'AE-068', 'عمرو مصطفي كمال الهنداوي', '67635a90f970ff8f22dac2133382ec68f7a4647f121678cb0bf7443a0dca4349'),
  (69, 'AE-069', 'مصطفى محمد محمد عبد الرسول', 'e7cdacc1343465a52cecbb951c685d1b9da10832d46f9af188f0ceac0a7eb63e'),
  (70, 'AE-070', 'احمد سبوت احمد اسماعيل', '00baef35d9649c07a28f337b9f8cdfc74df8b4fc348d968c0baadd7e41a7c888'),
  (71, 'AE-071', 'فادي زكري بدروس غبريال', '8684819a3dc8625cdeece65ef86d945b4ef059fb3cf08c67f3b038af326fc105'),
  (72, 'AE-072', 'محمد أحمد عبدالرازق حجازي', 'd9e5201be5abcbf73707a84c9633136ad5862895e404575eff965d6fe04abbc5'),
  (73, 'AE-073', 'حبيبة ايمن كامل علي', '1b531c5c8d60b680f3a0947c2f0de522a8cd6172f7f6a8aaac2eeaa6ab27839e'),
  (74, 'AE-074', 'عمرو مبروك الشحات مبروك سودان', '4f01866cd8153737cce6363d6541f0b0347461af39a232500192766950fed848'),
  (75, 'AE-075', 'ابراهيم محمد حسان على', '11b5333c57504c287c0eaa9c673e005b9aa193e34ada86f0b57452e137657475'),
  (76, 'AE-076', 'محمد أحمد محمد أحمد السيد', 'dc6b80e9ec96729e66fac69db9228c7c81def79cb4d80dd2dc76b893b8678557'),
  (77, 'AE-077', 'خالد محمد عبد العدل', 'dbe14329c6e263e18a27821e01ed109fb092f4f5a24f2b246baad76d3657a612'),
  (78, 'AE-078', 'مرام محمد احمد سليم', 'ee5a6784a676da2746b852254bc3de158e00a5b71a36f273dfee5d2282c7e3eb'),
  (79, 'AE-079', 'شهد عماد شوقي عبدالفتاح أحمد', '824f9ff7579332d61e590dd931bc2b711ed2a150f42643b9259d6a9adb316e76'),
  (80, 'AE-080', 'فرح اسلام حسنين ابراهيم', '82573beb8e8237c88da62e1ce900bae56ce8c119e8cf3e97fb9d2b469e5a9088'),
  (81, 'AE-081', 'عبدالرحمن أحمد أحمد محمد الشال', 'a66b33f56158480ae2ee6a38192aabbea4e92a35a2eec5b0cc7ec3152585c8ba'),
  (82, 'AE-082', 'أيمن محمد عبد المنعم عبدالجليل', '96968196f335b4cfcba936dbc9f5f88861d4d21311f2fb144229dadf1a19c117'),
  (83, 'AE-083', 'محمود محمد محمود حسب الله', '2b1bb0c5198325d7c055f384649847d365b5341355513fa53d724b0e29b042e4'),
  (84, 'AE-084', 'امنيه ابوالتنا عطيه', 'fbd826e81589832b179e3ee24b2f56d61ecdf4e09b1eda076d3ac64be90d312a'),
  (85, 'AE-085', 'احمد عبد النعيم عبد الرحيم فرغلي رويدي', '0acc5a6d0870fde192b8903e4cfe46b87429bdf14b9ab5570f90e363838172df'),
  (86, 'AE-086', 'عزالدين كرم محمد عبدالحافظ', '392070d9f8947cf5da117b17290dd3c9e004f10f115043cb98e986df148c209b'),
  (87, 'AE-087', 'شهد علي مصطفى رشوان', 'bebaff708cdb894b1e85951684485fc128ef7c846e5f3817272eac01ab0316e5'),
  (88, 'AE-088', 'ياسمين محمد مصطفى أحمد البديوي', 'eafd2e1f8afe3a41fdc39298443936210434189feb1731637a18a3dbf043bd0c'),
  (89, 'AE-089', 'عادل يوسف ابراهيم بركات', 'e22a800c4121831a10202bc6211aa5b3bbeed7c366d07b5b3fd246355aca9bd7'),
  (90, 'AE-090', 'محمد هشام حامد السباعي', '939e0e8b204ee5dd4dd7c4da71ff8efcc10daaa5efbf8f9a0899ba268bd1250b'),
  (91, 'AE-091', 'محمد حسين شعبان حسين الدفراوي', '4b746f11aa6a594faa03057715b5cc9a3e7be4d9ce22470db180e920f2671190'),
  (92, 'AE-092', 'عمر مصطفي ابوالفتوح ذكي', '80b48cbec63c0ba91023e4ab6b542d02ed8fab80fe14e122bdc7214eb551a721'),
  (93, 'AE-093', 'طارق عبدالحميد عبدالغني المزين', '7606a4c57ff43cc5581e5dc2a172d1e370e272c9631ba0fb94af5a58a04e1fa0'),
  (94, 'AE-094', 'مصطفى حسين علي منصور', '032b9718b03d8532c170422d43eab10c784e0ebe9c1e68bc0be5136449602064'),
  (95, 'AE-095', 'عبدالرحمن علاء الدين عبدالله محمد', 'b0b254338af5e6dc3de37eb4021aa206ca58a5a6557c26999308bf139b079b17'),
  (96, 'AE-096', 'احمد ياسر احمد عباس', '72bbfd552d25bc40a37bff346850bb074cb5a4a42a377da9ece5adc4febac8cc'),
  (97, 'AE-097', 'محمد حسنى بسيونى رمضان', '130ac6087f4f5ca055eb30426cae61a20e71e80b9aa752e027ad48d48ff11ce5'),
  (98, 'AE-098', 'عبدالله اسامه خميس محمد', 'e860ccd03907f6b3639ea2791594c32ea5fccec88ea001b4785f6c4bd16f0043'),
  (99, 'AE-099', 'الشيماء عبدالكريم أحمد رزق', '14f567d9782ca83c5b5f20d1f7d321d0b347799b54450c12c9316fafa0759ede'),
  (100, 'AE-100', 'ابراهيم صبحى الدمراوى', 'f9d8a4db5c1343df2117fced6d35e1239e737eca15a988b13f9b535b8e9aa191'),
  (101, 'AE-101', 'محمد عبدالعزيز عبدالجيد', '29f767ba1cc546dae483cc60e01b27df21e13a7dbc71f0956a2ce9600e084229'),
  (102, 'AE-102', 'عمرو علاء راغب احمد', '444e0672065598d7f25927e2d916e29f1bcd03393fff3116a96964638a43e64d')
on conflict (id) do nothing;

-- ---------- أكواد تفعيل الدكاترة (3 أكواد، كل كود لدكتور واحد) ----------
insert into public.staff_codes(code_hash) values
  ('43678495b6842f6dced9d94388b3c4fe5c4d5f96d61486c2796e360ebdd37d0b'),
  ('b4466402f20be9430c971ede41b4db8e7af89f4cc4c82a30d9403487ea1f5dbc'),
  ('94882ae5269b6cb6810a703f472b0566d176213a7b7ef793776a49e02a9349fe')
on conflict do nothing;
