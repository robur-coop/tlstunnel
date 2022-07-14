(* (c) 2019 Hannes Mehnert, all rights reserved *)

open Mirage

let frontend_port =
  let doc = Key.Arg.info ~doc:"The TCP port of the frontend." ["frontend-port"] in
  Key.(create "frontend_port" Arg.(opt int 443 doc))

let key =
  let doc = Key.Arg.info ~doc:"The shared secret" ["key"] in
  Key.(create "key" Arg.(required string doc))

let configuration_port =
  let doc = Key.Arg.info ~doc:"The TCP port for configuration." ["configuration-port"] in
  Key.(create "configuration_port" Arg.(opt int 1234 doc))

let dns_key =
  let doc = Key.Arg.info ~doc:"nsupdate key (name:type:value,...)" ["dns-key"] in
  Key.(create "dns-key" Arg.(required string doc))

let dns_server =
  let doc = Key.Arg.info ~doc:"dns server IP" ["dns-server"] in
  Key.(create "dns-server" Arg.(required ip_address doc))

let domains =
  let doc = Key.Arg.info ~doc:"domains" ["domains"] in
  Key.(create "domains" Arg.(required (list string) doc))

let key_seed =
  let doc = Key.Arg.info ~doc:"certificate key seed" ["key-seed"] in
  Key.(create "key-seed" Arg.(required string doc))

let main =
  foreign
    ~keys:[ Key.v frontend_port ;
            Key.v key ;
            Key.v configuration_port ;
            Key.v dns_key ;
            Key.v dns_server ;
            Key.v domains ;
            Key.v key_seed ;
          ]
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

let () =
  register "tlstunnel"
    [ main $ default_random $ default_time $ default_posix_clock $ block $ stack $ private_stack ]
