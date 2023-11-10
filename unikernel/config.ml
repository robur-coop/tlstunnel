(* (c) 2019 Hannes Mehnert, all rights reserved *)

open Mirage

let main =
  foreign
    ~packages:[
      package ~min:"0.14.0" "tls-mirage" ;
      package ~min:"5.0.1" ~sublibs:["mirage"] "dns-certify" ;
      package ~min:"6.0.0" "cstruct" ;
      package ~min:"7.0.0" "tcpip" ;
    ]
    "Unikernel.Main"
    (random @-> time @-> pclock @-> block @-> stackv4v6 @-> stackv4v6 @-> job)

let stack = generic_stackv4v6 default_network

let private_stack =
  generic_stackv4v6 ~group:"private" (netif ~group:"private" "private")

let block =
  Key.(if_impl is_solo5 (block_of_file "storage") (block_of_file "disk.img"))

let enable_monitoring =
  let doc = Cmdliner.Arg.info
      ~doc:"Enable monitoring (only available for solo5 targets)"
      [ "enable-monitoring" ]
  in
  Key.(create "enable-monitoring" Arg.(flag doc))

let management_stack =
  if_impl
    (Key.value enable_monitoring)
    (generic_stackv4v6 ~group:"management" (netif ~group:"management" "management"))
    stack

let (name : string Runtime_key.key) = Runtime_key.create "Unikernel.K.name"

let monitoring =
  let monitor = Runtime_key.create "Unikernel.K.monitor" in
  let connect _ modname = function
    | [ _ ; _ ; stack ] ->
      Fmt.str "Lwt.return (match %a with\
               | None -> Logs.warn (fun m -> m \"no monitor specified, not outputting statistics\")\
               | Some ip -> %s.create ip ~hostname:%a %s)"
        Runtime_key.call monitor modname
        Runtime_key.call name stack
    | _ -> assert false
  in
  impl
    ~packages:[ package "mirage-monitoring" ]
    ~runtime_keys:[ Runtime_key.v name ; Runtime_key.v monitor ]
    ~connect "Mirage_monitoring.Make"
    (time @-> pclock @-> stackv4v6 @-> job)

let syslog =
  let syslog = Runtime_key.create "Unikernel.K.syslog" in
  let connect _ modname = function
    | [ _ ; stack ] ->
      Fmt.str "Lwt.return (match %a with\
               | None -> Logs.warn (fun m -> m \"no syslog specified, dumping on stdout\")\
               | Some ip -> Logs.set_reporter (%s.create %s ip ~hostname:%a ()))"
        Runtime_key.call syslog modname stack
        Runtime_key.call name
    | _ -> assert false
  in
  impl
    ~packages:[ package ~sublibs:["mirage"] ~min:"0.4.0" "logs-syslog" ]
    ~runtime_keys:[ Runtime_key.v name ; Runtime_key.v syslog ]
    ~connect "Logs_syslog_mirage.Udp"
    (pclock @-> stackv4v6 @-> job)


type i0 = I0
let i0 = Functoria.Type.v I0
let no0 = Functoria.impl "Int" job

type n1 = N1
let n1 = Functoria.Type.v N1
let noop1 = Functoria.impl "Set.Make" (job @-> job)

let optional_monitoring time pclock stack =
  if_impl (Key.value enable_monitoring)
    (monitoring $ time $ pclock $ stack)
    (noop1 $ no0)

let optional_syslog pclock stack =
  if_impl (Key.value enable_monitoring)
    (syslog $ pclock $ stack)
    (noop1 $ no0)

let () =
  register "tlstunnel"
    [
      optional_syslog default_posix_clock management_stack ;
      optional_monitoring default_time default_posix_clock management_stack ;
      main $ default_random $ default_time $ default_posix_clock $ block $ stack $ private_stack
    ]
