module Make (Block : Mirage_block.S) = struct
  module H = Digestif.SHA256

  let s_version = 1

  module IS = Set.Make(Int64)

  type superblock = {
    super_version : int ; (* 2 byte *)
    (* padding - 6 byte *)
    super_counter : int ; (* 8 byte *)
    timestamp : Ptime.t ; (* 8 byte *)
    active_sector : int64 ; (* 8 byte *)
    data_length : int ; (* 8 byte *)
    data_checksum : string ;
    (* padding until length - 32 *)
    (* superblock_checksum : string ; *)
    used_sectors : IS.t ; (* not persistent *)
  }

  let superblock_size = 40 + 2 * H.digest_size

  let empty_superblock () = {
    super_version = s_version ;
    super_counter = 0 ;
    timestamp = Mirage_ptime.now () ;
    active_sector = 0L ;
    data_length = 0 ;
    data_checksum = "" ;
    used_sectors = IS.empty ;
  }

  let ns_per_day = Int64.mul 86_000L 1_000_000_000L
  let ps_per_ns = 1_000L

  let decode_timestamp data off =
    let ns = String.get_int64_be data off in
    let d = Int64.unsigned_div ns ns_per_day
    and ps = Int64.(mul (unsigned_rem ns ns_per_day) ps_per_ns)
    in
    Ptime.v (Int64.to_int d, ps)

  let encode_timestamp data off v =
    let d, ps = Ptime.Span.to_d_ps (Ptime.to_span v) in
    let ns = Int64.(add (mul (Int64.of_int d) ns_per_day) (div ps ps_per_ns)) in
    Bytes.set_int64_be data off ns

  let safe_int ~msg d =
    if d > Int64.of_int max_int then
      Error (`Overflow msg)
    else
      Ok (Int64.to_int d)

  type decode_err =
    [ `Overflow of string |`Bad_checksum | `Bad_superblock_version of int ]

  let pp_decode_err ppf = function
    | `Overflow msg -> Fmt.pf ppf "integer overflow %s" msg
    | `Bad_checksum -> Fmt.string ppf "bad superblock checksum"
    | `Bad_superblock_version v ->
      Fmt.pf ppf "superblock version %d is not supported (supported is %d)"
        v s_version

  let decode_superblock buf : (superblock, [> decode_err ]) result =
    let payload, checksum =
      let mid = String.length buf - H.digest_size in
      String.sub buf 0 mid, String.sub buf mid H.digest_size
    in
    if String.equal checksum H.(to_raw_string (digest_string payload)) then
      let super_version = String.get_uint16_be payload 0
      and super_counter = String.get_int64_be payload 8
      and timestamp = decode_timestamp payload 16
      and active_sector = String.get_int64_be payload 24
      and data_length = String.get_int64_be payload 32
      and data_checksum = String.sub payload 40 H.digest_size
      in
      let ( let* ) = Result.bind in
      if super_version = s_version then
        let* super_counter = safe_int ~msg:"superblock counter" super_counter in
        let* data_length = safe_int ~msg:"data length" data_length in
        Ok { super_version ; super_counter ; timestamp ; active_sector ;
             data_length ; data_checksum ; used_sectors = IS.empty }
      else
        Error (`Bad_superblock_version super_version)
    else
      Error `Bad_checksum

  let encode_superblock t buf =
    Bytes.set_uint16_be buf 0 t.super_version;
    Bytes.set_int64_be buf 8 (Int64.of_int t.super_counter);
    encode_timestamp buf 16 t.timestamp;
    Bytes.set_int64_be buf 24 t.active_sector;
    Bytes.set_int64_be buf 32 (Int64.of_int t.data_length);
    Bytes.blit_string t.data_checksum 0 buf 40 H.digest_size;
    let eop = Bytes.length buf - H.digest_size in
    let payload = Bytes.sub_string buf 0 eop in
    let checksum = H.(to_raw_string (digest_string payload)) in
    Bytes.blit_string checksum 0 buf eop H.digest_size

  let lwt_err_to_msg ~pp_error f =
    let open Lwt.Infix in
    f >|= Result.map_error (fun e -> `Msg (Fmt.to_to_string pp_error e))

  let read_data block =
    let open Lwt.Infix in
    Block.get_info block >>= fun info ->
    let open Lwt_result.Infix in
    let ss = info.Mirage_block.sector_size in
    assert (ss >= superblock_size);
    let data_per_sector = ss - 8 in (* each sector is prefixed by a next pointer *)
    let super_data_first, super_data_last = Cstruct.create ss, Cstruct.create ss in
    let first_super, last_super = 0L, Int64.pred info.Mirage_block.size_sectors in
    lwt_err_to_msg ~pp_error:Block.pp_error
      (Block.read block first_super [ super_data_first ]) >>= fun () ->
    lwt_err_to_msg ~pp_error:Block.pp_error
      (Block.read block last_super [ super_data_last ]) >>= fun () ->
    Lwt_result.lift
      (match decode_superblock (Cstruct.to_string super_data_first),
             decode_superblock (Cstruct.to_string super_data_last)
       with
       | Ok a, Ok b ->
         (match compare a.super_counter b.super_counter with
          | 0 -> Ok (a, None)
          | 1 -> Ok (a, Some (last_super, super_data_first))
          | -1 -> Ok (b, Some (first_super, super_data_last))
          | _ -> assert false)
       | Error `Bad_checksum, Ok b -> Ok (b, Some (first_super, super_data_last))
       | Ok a, Error `Bad_checksum -> Ok (a, Some (last_super, super_data_first))
       | Error a, _ -> Error a
       | _, Error b -> Error b) >>= fun (superblock, to_write) ->
    let scratch = Cstruct.create ss in
    let rec read_one sectors data sector =
      match sector = 0L, Cstruct.length data = 0 with
      | true, true -> Lwt.return (Ok sectors)
      | false, false ->
        lwt_err_to_msg ~pp_error:Block.pp_error
          (Block.read block sector [ scratch ]) >>= fun () ->
        let next = Cstruct.BE.get_uint64 scratch 0 in
        let len = min (Cstruct.length data) data_per_sector in
        Cstruct.blit scratch 8 data 0 len;
        read_one (IS.add sector sectors) (Cstruct.shift data len) next
      | true, false -> Lwt.return (Error (`Msg "early end of data"))
      | false, true -> Lwt.return (Error (`Msg "sector chain exceeds data"))
    in
    let data = Cstruct.create superblock.data_length in
    read_one IS.empty data superblock.active_sector >>= fun used_sectors ->
    let data = Cstruct.to_string data in
    if String.equal superblock.data_checksum H.(to_raw_string (digest_string data)) then
      (match to_write with
       | None -> Lwt.return (Ok ())
       | Some (idx, d) ->
         lwt_err_to_msg ~pp_error:Block.pp_write_error
           (Block.write block idx [ d ])) >|= fun () ->
      { superblock with used_sectors }, data
    else
      Lwt.return (Error (`Msg "bad data checksum"))

  let write_data block old_superblock data =
    let open Lwt.Infix in
    (* first check that we could write data on block without overwriting the old data *)
    Block.get_info block >>= fun info ->
    let ss = info.Mirage_block.sector_size
    and sectors = info.Mirage_block.size_sectors
    in
    assert (ss >= superblock_size);
    let data = Cstruct.of_string data in
    let data_per_sector = ss - 8 in (* each sector is prefixed by a next pointer *)
    let sectors_needed = (Cstruct.length data + (pred ss)) / data_per_sector in
    if 2 + sectors_needed + IS.cardinal old_superblock.used_sectors > Int64.to_int sectors then
      Lwt.return (Error (`Msg "not enough blocks"))
    else
      (* write data *)
      let open Lwt_result.Infix in
      let data_sector = Cstruct.create ss in
      let rec is_free i =
        if Int64.succ i >= sectors then
          Error (`Msg "no more sectors") (* according to the test above this should not happen *)
        else if IS.mem i old_superblock.used_sectors then
          is_free (Int64.succ i)
        else
          Ok i
      in
      let rec write_one sector data acc =
        (if Cstruct.length data <= data_per_sector then
           Lwt.return (Ok 0L)
         else
           Lwt_result.lift (is_free (Int64.succ sector))) >>= fun next ->
        Cstruct.BE.set_uint64 data_sector 0 next;
        let len = min (Cstruct.length data) data_per_sector in
        Cstruct.blit data 0 data_sector 8 len;
        lwt_err_to_msg ~pp_error:Block.pp_write_error
          (Block.write block sector [ data_sector ]) >>= fun () ->
        let acc' = IS.add sector acc in
        if next = 0L then
          Lwt.return (Ok acc')
        else
          write_one next (Cstruct.shift data data_per_sector) acc'
      in
      Lwt_result.lift (is_free 1L) >>= fun first_sector ->
      write_one first_sector data IS.empty >>= fun used_sectors ->
      let superblock =
        let empty = empty_superblock () in
        {
          empty with
          super_counter = succ old_superblock.super_counter ;
          active_sector = first_sector ;
          data_length = Cstruct.length data ;
          data_checksum = H.(to_raw_string (digest_string (Cstruct.to_string data))) ;
          used_sectors ;
        }
      in
      let s = Bytes.create ss in
      encode_superblock superblock s;
      let s = Cstruct.of_bytes s in
      lwt_err_to_msg ~pp_error:Block.pp_write_error
        (Block.write block (Int64.pred sectors) [ s ]) >>= fun () ->
      lwt_err_to_msg ~pp_error:Block.pp_write_error
        (Block.write block 0L [ s ]) >|= fun () ->
      superblock

  let init block =
    let open Lwt.Infix in
    let superblock =
      let empty = empty_superblock () in
      { empty with data_checksum = H.(to_raw_string (digest_string "")) }
    in
    Block.get_info block >>= fun info ->
    let ss = info.Mirage_block.sector_size in
    assert (ss >= superblock_size);
    let s = Bytes.create ss in
    encode_superblock superblock s;
    let last_sector = Int64.pred info.Mirage_block.size_sectors in
    let open Lwt_result.Infix in
    let s = Cstruct.of_bytes s in
    lwt_err_to_msg ~pp_error:Block.pp_write_error
      (Block.write block last_sector [ s ]) >>= fun () ->
    lwt_err_to_msg ~pp_error:Block.pp_write_error
      (Block.write block 0L [ s ]) >|= fun () ->
    superblock
end
