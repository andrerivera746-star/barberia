-- ============================================================
-- POLITICAS DE SEGURIDAD (RLS) PARA EL PROYECTO BARBERIA
-- ============================================================
-- Cómo aplicarlo:
--   1. Entra a tu proyecto en supabase.com/dashboard
--   2. Ve a SQL Editor -> New query
--   3. Pega TODO este archivo y dale Run
--   4. Revisa los mensajes de resultado (no debería haber errores)
--
-- Qué hace este script:
--   - Arregla la fuga confirmada: clientes_worker_view era legible
--     por cualquiera sin login (exponía nombre y celular de clientes).
--   - Activa Row Level Security (RLS) en todas las tablas de la app
--     y agrega políticas que reflejan exactamente los permisos que
--     ya usa el código: admin ve/edita todo, cada trabajador solo
--     ve/edita lo suyo (sus pagos, su asistencia, su ficha).
--   - Es seguro volver a correrlo más de una vez (usa "IF EXISTS" /
--     "OR REPLACE" en todos lados).
--
-- IMPORTANTE - revisa antes de correr:
--   - Este script asume que las columnas "id" de tus tablas son de
--     tipo texto (así las genera el front-end, ej. "c_kx1a2b3"). Si
--     en tu esquema son "uuid", los tipos igual deberían coincidir
--     entre columnas relacionadas (workerid <-> trabajadores.id), así
--     que no debería requerir cambios. Si algo falla por tipos,
--     avisame el mensaje de error exacto.
-- ============================================================


-- ------------------------------------------------------------
-- 1) FUNCIÓN AUXILIAR: ¿el usuario logueado es admin?
--    Lee el rol desde app_metadata del JWT (lo mismo que usa el
--    front-end en session.user.app_metadata.role).
-- ------------------------------------------------------------
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin',
    false
  );
$$;


-- ------------------------------------------------------------
-- 2) ARREGLO INMEDIATO: clientes_worker_view
--    Esta vista quedaba accesible sin login (confirmado: 2 filas
--    con name/phone leídas con la key anónima). Se bloquea el
--    acceso anónimo y se deja solo para usuarios logueados.
-- ------------------------------------------------------------
revoke all on public.clientes_worker_view from anon;
revoke all on public.clientes_worker_view from public;
grant select on public.clientes_worker_view to authenticated;


-- ------------------------------------------------------------
-- 3) TABLA: clientes
--    Admin: todo. Trabajador: puede crear clientes nuevos (flujo
--    de "cliente nuevo" al atender), pero no lista la tabla
--    completa (para eso usa clientes_worker_view, ya restringida).
-- ------------------------------------------------------------
alter table public.clientes enable row level security;

drop policy if exists "clientes_select_admin" on public.clientes;
create policy "clientes_select_admin"
  on public.clientes for select
  to authenticated
  using (is_admin());

drop policy if exists "clientes_insert_authenticated" on public.clientes;
create policy "clientes_insert_authenticated"
  on public.clientes for insert
  to authenticated
  with check (true);

drop policy if exists "clientes_update_admin" on public.clientes;
create policy "clientes_update_admin"
  on public.clientes for update
  to authenticated
  using (is_admin())
  with check (is_admin());

drop policy if exists "clientes_delete_admin" on public.clientes;
create policy "clientes_delete_admin"
  on public.clientes for delete
  to authenticated
  using (is_admin());


-- ------------------------------------------------------------
-- 4) TABLA: trabajadores
--    Admin: ve todos y puede editar (ej. % de comisión).
--    Trabajador: solo puede ver su propia ficha (user_id = su auth.uid()).
--    Crear/editar/eliminar cuentas de trabajador se hace SOLO vía la
--    Edge Function "manage-worker" (usa service_role, no pasa por RLS),
--    así que no hay política de INSERT/DELETE para usuarios normales.
-- ------------------------------------------------------------
alter table public.trabajadores enable row level security;

drop policy if exists "trabajadores_select_admin_or_own" on public.trabajadores;
create policy "trabajadores_select_admin_or_own"
  on public.trabajadores for select
  to authenticated
  using (is_admin() or user_id = auth.uid());

drop policy if exists "trabajadores_update_admin" on public.trabajadores;
create policy "trabajadores_update_admin"
  on public.trabajadores for update
  to authenticated
  using (is_admin())
  with check (is_admin());


-- ------------------------------------------------------------
-- 5) TABLA: pagos
--    Admin: todo. Trabajador: solo sus propios pagos/cortes
--    (workerid = el id de su propia fila en trabajadores).
-- ------------------------------------------------------------
alter table public.pagos enable row level security;

drop policy if exists "pagos_select_admin_or_own" on public.pagos;
create policy "pagos_select_admin_or_own"
  on public.pagos for select
  to authenticated
  using (
    is_admin()
    or workerid = (select id from public.trabajadores where user_id = auth.uid())
  );

drop policy if exists "pagos_insert_admin_or_own" on public.pagos;
create policy "pagos_insert_admin_or_own"
  on public.pagos for insert
  to authenticated
  with check (
    is_admin()
    or workerid = (select id from public.trabajadores where user_id = auth.uid())
  );

drop policy if exists "pagos_update_admin_or_own" on public.pagos;
create policy "pagos_update_admin_or_own"
  on public.pagos for update
  to authenticated
  using (
    is_admin()
    or workerid = (select id from public.trabajadores where user_id = auth.uid())
  )
  with check (
    is_admin()
    or workerid = (select id from public.trabajadores where user_id = auth.uid())
  );

drop policy if exists "pagos_delete_admin_or_own" on public.pagos;
create policy "pagos_delete_admin_or_own"
  on public.pagos for delete
  to authenticated
  using (
    is_admin()
    or workerid = (select id from public.trabajadores where user_id = auth.uid())
  );


-- ------------------------------------------------------------
-- 6) TABLA: asistencias
--    Mismo criterio que pagos: admin ve todo, trabajador solo la suya.
-- ------------------------------------------------------------
alter table public.asistencias enable row level security;

drop policy if exists "asistencias_select_admin_or_own" on public.asistencias;
create policy "asistencias_select_admin_or_own"
  on public.asistencias for select
  to authenticated
  using (
    is_admin()
    or workerid = (select id from public.trabajadores where user_id = auth.uid())
  );

drop policy if exists "asistencias_insert_admin_or_own" on public.asistencias;
create policy "asistencias_insert_admin_or_own"
  on public.asistencias for insert
  to authenticated
  with check (
    is_admin()
    or workerid = (select id from public.trabajadores where user_id = auth.uid())
  );

drop policy if exists "asistencias_update_admin_or_own" on public.asistencias;
create policy "asistencias_update_admin_or_own"
  on public.asistencias for update
  to authenticated
  using (
    is_admin()
    or workerid = (select id from public.trabajadores where user_id = auth.uid())
  )
  with check (
    is_admin()
    or workerid = (select id from public.trabajadores where user_id = auth.uid())
  );


-- ------------------------------------------------------------
-- 7) TABLA: servicios
--    Catálogo de servicios: todos los logueados lo leen (para elegir
--    servicio al atender), solo admin lo edita.
-- ------------------------------------------------------------
alter table public.servicios enable row level security;

drop policy if exists "servicios_select_authenticated" on public.servicios;
create policy "servicios_select_authenticated"
  on public.servicios for select
  to authenticated
  using (true);

drop policy if exists "servicios_insert_admin" on public.servicios;
create policy "servicios_insert_admin"
  on public.servicios for insert
  to authenticated
  with check (is_admin());

drop policy if exists "servicios_update_admin" on public.servicios;
create policy "servicios_update_admin"
  on public.servicios for update
  to authenticated
  using (is_admin())
  with check (is_admin());

drop policy if exists "servicios_delete_admin" on public.servicios;
create policy "servicios_delete_admin"
  on public.servicios for delete
  to authenticated
  using (is_admin());


-- ------------------------------------------------------------
-- 8) TABLA: productos
--    Catálogo + stock: todos los logueados leen. Solo admin crea o
--    elimina productos. Actualizar (incluye descuento de stock al
--    vender) lo puede hacer cualquier logueado, ya que el trabajador
--    necesita descontar stock al registrar una venta.
--    Nota: esto permite en teoría que un trabajador cambie precio/
--    nombre de un producto vía API directa (no solo el stock). Si
--    querés restringirlo más (que el trabajador SOLO pueda tocar
--    "stock"), avisame y armamos una función RPC dedicada para eso.
-- ------------------------------------------------------------
alter table public.productos enable row level security;

drop policy if exists "productos_select_authenticated" on public.productos;
create policy "productos_select_authenticated"
  on public.productos for select
  to authenticated
  using (true);

drop policy if exists "productos_insert_admin" on public.productos;
create policy "productos_insert_admin"
  on public.productos for insert
  to authenticated
  with check (is_admin());

drop policy if exists "productos_update_authenticated" on public.productos;
create policy "productos_update_authenticated"
  on public.productos for update
  to authenticated
  using (true)
  with check (true);

drop policy if exists "productos_delete_admin" on public.productos;
create policy "productos_delete_admin"
  on public.productos for delete
  to authenticated
  using (is_admin());


-- ------------------------------------------------------------
-- 9) TABLA: comision_niveles
--    Configuración de comisiones: todos los logueados la leen (para
--    calcular la comisión en pantalla), solo admin la edita.
-- ------------------------------------------------------------
alter table public.comision_niveles enable row level security;

drop policy if exists "comision_niveles_select_authenticated" on public.comision_niveles;
create policy "comision_niveles_select_authenticated"
  on public.comision_niveles for select
  to authenticated
  using (true);

drop policy if exists "comision_niveles_insert_admin" on public.comision_niveles;
create policy "comision_niveles_insert_admin"
  on public.comision_niveles for insert
  to authenticated
  with check (is_admin());

drop policy if exists "comision_niveles_update_admin" on public.comision_niveles;
create policy "comision_niveles_update_admin"
  on public.comision_niveles for update
  to authenticated
  using (is_admin())
  with check (is_admin());

drop policy if exists "comision_niveles_delete_admin" on public.comision_niveles;
create policy "comision_niveles_delete_admin"
  on public.comision_niveles for delete
  to authenticated
  using (is_admin());


-- ------------------------------------------------------------
-- 10) TABLA: movimientos_inventario
--     Log de movimientos de stock: cualquier logueado puede
--     registrar un movimiento; solo admin puede leer el historial
--     (es un log de auditoría). No se permite editar ni borrar
--     (registro inmutable).
-- ------------------------------------------------------------
alter table public.movimientos_inventario enable row level security;

drop policy if exists "movimientos_select_admin" on public.movimientos_inventario;
create policy "movimientos_select_admin"
  on public.movimientos_inventario for select
  to authenticated
  using (is_admin());

drop policy if exists "movimientos_insert_authenticated" on public.movimientos_inventario;
create policy "movimientos_insert_authenticated"
  on public.movimientos_inventario for insert
  to authenticated
  with check (true);


-- ============================================================
-- FIN DEL SCRIPT
-- ============================================================
-- Después de correrlo, probá la app normalmente (login admin y
-- login trabajador) para confirmar que todo sigue funcionando.
-- Si algo se rompe (ej. "new row violates row-level security
-- policy"), copiame el mensaje de error exacto y ajustamos la
-- política correspondiente.
-- ============================================================
