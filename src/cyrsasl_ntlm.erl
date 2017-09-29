%%%----------------------------------------------------------------------
%%% File    : cyrsasl_ntlm.erl
%%% Author  : Dmitry Kirillov <kirillov_dmitry@mail.ru>
%%% Purpose : NTLM SASL mechanism
%%% Created : 25 Jul 2009 by Dmitry Kirillov <kirillov_dmitry@mail.ru>
%%%
%%% Based on cyrsasl_digest.erl by Alexey Shchepin
%%%
%%% ejabberd, Copyright (C) 2002-2009   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this program; if not, write to the Free Software
%%% Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
%%% 02111-1307 USA
%%%
%%%----------------------------------------------------------------------

-module(cyrsasl_ntlm).
-author('kirillov_dmitry@mail.ru').

-export([start/1,
         stop/0,
         mech_new/4,
         mech_step/2,
         opt_type/1,
         format_error/1]).

-include("ejabberd.hrl").
-include("esmb/esmb_lib.hrl").
-include("logger.hrl").

-behaviour(ejabberd_config).

-behaviour(cyrsasl).

-type error_reason() :: unsupported_extension | bad_username | 
        not_authorized | saslprep_failed | 
        parser_failed | bad_attribute | nonce_mismatch |
        bad_channel_binding | unexpected_response.

-export_type([error_reason/0]).

-record(state, {step, nonce, username, authzid, get_password, auth_module,
                host, sockOpt, negotiate}).
-record(ntlmtype1mes, {signature, message_type, flags, domain, workstation}).
-record(ntlmtype2mes, {signature, message_type, flags, challenge, context, target_name}).
-record(ntlmtype3mes, { signature, message_type, lm_response, ntlm_response, 
            target_name, user_name, workstation_name, session_key, flags}).

-define(NTLM_SIGNATURE, <<78,84,76,77,83,83,80,0>>).
-define(NtLmNegotiate,     1).
-define(NtLmChallenge,     2).
-define(NtLmAuthenticate,  3).
-define(FLAGS_Negotiate_Unicode,        16#00000001).   % Indicates that Unicode strings are supported for use in security buffer data.
-define(FLAGS_Negotiate_OEM,            16#00000002).   % Indicates that OEM strings are supported for use in security buffer data.
-define(FLAGS_Request_Target,           16#00000004).   % Requests that the server's authentication realm be included in the Type 2 message.
-define(FLAGS_Negotiate_Sign,           16#00000010).   % Specifies that authenticated communication between the client and server should carry a digital signature (message integrity).
-define(FLAGS_Negotiate_Seal,           16#00000020).   % Specifies that authenticated communication between the client and server should be encrypted (message confidentiality).
-define(FLAGS_Negotiate_Datagram_Style, 16#00000040).   % Indicates that datagram authentication is being used.
-define(FLAGS_Negotiate_Lan_Manager_Key,16#00000080).   % Indicates that the Lan Manager Session Key should be used for signing and sealing authenticated communications.
-define(FLAGS_Negotiate_Netware,        16#00000100).   % This flag's usage has not been identified.
-define(FLAGS_Negotiate_NTLM,           16#00000200).   % Indicates that NTLM authentication is being used.
-define(FLAGS_Negotiate_Anonymous,      16#00000800).   % Sent by the client in the Type 3 message to indicate that an anonymous context has been established. This also affects the response fields (as detailed in the "Anonymous Response" section).
-define(FLAGS_Negotiate_Domain_Supplied,16#00001000).   % Sent by the client in the Type 1 message to indicate that the name of the domain in which the client workstation has membership is included in the message. This is used by the server to determine whether the client is eligible for local authentication.
-define(FLAGS_Negotiate_Workstation_Supplied, 16#00002000). % Sent by the client in the Type 1 message to indicate that the client workstation's name is included in the message. This is used by the server to determine whether the client is eligible for local authentication.
-define(FLAGS_Negotiate_Local_Call,     16#00004000).   % Sent by the server to indicate that the server and client are on the same machine. Implies that the client may use the established local credentials for authentication instead of calculating a response to the challenge.
-define(FLAGS_Negotiate_Always_Sign,    16#00008000).   % Indicates that authenticated communication between the client and server should be signed with a "dummy" signature.
-define(FLAGS_Target_Type_Domain,       16#00010000).   % Sent by the server in the Type 2 message to indicate that the target authentication realm is a domain.
-define(FLAGS_Target_Type_Server,       16#00020000).   % Sent by the server in the Type 2 message to indicate that the target authentication realm is a server.
-define(FLAGS_Target_Type_Share,        16#00040000).   % Sent by the server in the Type 2 message to indicate that the target authentication realm is a share. Presumably, this is for share-level authentication. Usage is unclear.
-define(FLAGS_Negotiate_NTLM2_Key,      16#00080000).   % Indicates that the NTLM2 signing and sealing scheme should be used for protecting authenticated communications. Note that this refers to a particular session security scheme, and is not related to the use of NTLMv2 authentication. This flag can, however, have an effect on the response calculations (as detailed in the "NTLM2 Session Response" section).
-define(FLAGS_Request_Init_Response,    16#00100000).   % This flag's usage has not been identified.
-define(FLAGS_Request_Accept_Response,  16#00200000).   % This flag's usage has not been identified.
-define(FLAGS_Request_Non_NT_Session_Key, 16#00400000). % This flag's usage has not been identified.
-define(FLAGS_Negotiate_Target_Info,    16#00800000).   % Sent by the server in the Type 2 message to indicate that it is including a Target Information block in the message. The Target Information block is used in the calculation of the NTLMv2 response.
-define(FLAGS_Negotiate_128,            16#20000000).   % Indicates that 128-bit encryption is supported.
-define(FLAGS_Negotiate_Key_Exchange,   16#40000000).   % Indicates that the client will provide an encrypted master key in the "Session Key" field of the Type 3 message.
-define(FLAGS_Negotiate_56,             16#80000000).   % Indicates that 56-bit encryption is supported. 

start(_Opts) ->
    cyrsasl:register_mechanism(<<"NTLM">>, ?MODULE, plain),
    ejabberd:start_app(iconv),    esmb:start().
    
stop() ->
    ok.

-spec format_error(error_reason()) -> {atom(), binary()}.
format_error(unsupported_extension) ->
    {'bad-protocol', <<"Unsupported extension">>};
format_error(bad_username) ->
    {'invalid-authzid', <<"Malformed username">>};
format_error(not_authorized) ->
    {'not-authorized', <<"Invalid username or password">>};
format_error(saslprep_failed) ->
    {'not-authorized', <<"SASLprep failed">>};
format_error(parser_failed) ->
    {'bad-protocol', <<"Response decoding failed">>};
format_error(bad_attribute) ->
    {'bad-protocol', <<"Malformed or unexpected attribute">>};
format_error(nonce_mismatch) ->
    {'bad-protocol', <<"Nonce mismatch">>};
format_error(bad_channel_binding) ->
    {'bad-protocol', <<"Invalid channel binding">>};
format_error(unexpected_response) ->
    {'bad-protocol', <<"Unexpected response">>};
format_error(_) ->
    <<"unexpected dialback result">>.


mech_new(Host, GetPassword, _CheckPassword, _CheckPasswordDigest) ->
    {ok, #state{step = 1,
                nonce = randoms:get_string(),
                host = Host,
                get_password = GetPassword}}.

mech_step(#state{step = 1, nonce = Nonce} = State, _) ->
    {continue,
     <<"nonce=\"", Nonce/binary,
     "\",qop=\"auth\",charset=utf-8,algorithm=md5-sess">>,
     State#state{step = 3}};

mech_step(#state{step = 3} = State, ClientIn) ->
    case dec_NTLMType1Mes(ClientIn) of
    {ok,Mes1} ->
        ?DEBUG("cyrsasl_ntlm: NTLM Message Type 1 Received.",[]),
        ?DEBUG("cyrsasl_ntlm: Message=~p",[Mes1]),
        echo_flags(Mes1#ntlmtype1mes.flags),
        PDC = ejabberd_config:get_option({ntlmpdc, State#state.host}, <<"192.168.1.1">>),
        case esmb:connect(PDC) of
        {ok,S,Neg} ->
            ?DEBUG("cyrsasl_ntlm: SMB:Connect to ~s ok.",[PDC]),
            EncKey = Neg#smb_negotiate_res.encryption_key,
                    if 
		       (Mes1#ntlmtype1mes.flags band ?FLAGS_Negotiate_Unicode) > 0 ->
		          if
		            (Mes1#ntlmtype1mes.flags band ?FLAGS_Request_Target) > 0 ->
                    Type2Flag = ?FLAGS_Negotiate_Unicode bor ?FLAGS_Request_Target bor ?FLAGS_Negotiate_NTLM bor ?FLAGS_Negotiate_Always_Sign bor ?FLAGS_Target_Type_Server bor ?FLAGS_Negotiate_Sign,
                    TargetName = PDC;
                true ->
                    Type2Flag = ?FLAGS_Negotiate_Unicode bor ?FLAGS_Negotiate_NTLM bor ?FLAGS_Negotiate_Always_Sign bor ?FLAGS_Target_Type_Server bor ?FLAGS_Negotiate_Sign,
                    TargetName = undefined
                end;
            true ->
		          if
		            (Mes1#ntlmtype1mes.flags band ?FLAGS_Request_Target) > 0 ->
                    Type2Flag = ?FLAGS_Negotiate_OEM bor ?FLAGS_Request_Target bor ?FLAGS_Negotiate_NTLM bor ?FLAGS_Negotiate_Always_Sign bor ?FLAGS_Target_Type_Server bor ?FLAGS_Negotiate_Sign,
                    TargetName = PDC;
                true ->
                    Type2Flag = ?FLAGS_Negotiate_OEM bor ?FLAGS_Negotiate_NTLM bor ?FLAGS_Negotiate_Always_Sign bor ?FLAGS_Target_Type_Server bor ?FLAGS_Negotiate_Sign,
                    TargetName = undefined
                end
            end,
            RecResp = #ntlmtype2mes{signature = ?NTLM_SIGNATURE, message_type = ?NtLmChallenge, 
                                    flags = Type2Flag, challenge = EncKey, context = 0, target_name = TargetName},
            ?DEBUG("cyrsasl_ntlm: Record of NTLM Type 2 Message(response): ~p",[RecResp]),
            echo_flags(RecResp#ntlmtype2mes.flags),
            Resp = enc_NTLMType2Mes(RecResp),
            ?DEBUG("cyrsasl_ntlm: NTLM Type 2 Message(response):=~p",[Resp]),
          
		    {continue, Resp,
		     State#state{step = 5, sockOpt = S, negotiate = Neg}};
        Else ->
            ?DEBUG("cyrsasl_ntlm: SMB:Failed to connect:~s, Error: ~p",[PDC,Else]),
            {error, unexpected_response}
        end;
    _ ->
        ?DEBUG("cyrsasl_ntlm: NTLM Message Type 1 Error!",[]),
        {error, unexpected_response}
    end;
    
mech_step(#state{step = 5, sockOpt = S, negotiate = Neg} = State, ClientIn) ->
    case dec_NTLMType3Mes(ClientIn) of
    {ok,Mes3} ->
        ?DEBUG("cyrsasl_ntlm: NTLM Message Type 3 Received.",[]),
        ?DEBUG("cyrsasl_ntlm: Message=~p",[Mes3]),
        echo_flags(Mes3#ntlmtype3mes.flags),
        if (Mes3#ntlmtype3mes.flags band ?FLAGS_Negotiate_Unicode) > 0 ->
            User = ucs2_to_cset(binary_to_list(Mes3#ntlmtype3mes.user_name), "ASCII"),
            Domain = ucs2_to_cset(binary_to_list(Mes3#ntlmtype3mes.target_name), "ASCII");
        true ->
            User = binary_to_list(Mes3#ntlmtype3mes.user_name),
            Domain = binary_to_list(Mes3#ntlmtype3mes.target_name)
        end,
        U = #user{name = User, primary_domain = Domain, auth_domain = Domain},
        ?DEBUG("cyrsasl_ntlm: SMB:User record: ~p",[U]),
               
        LM_hash = Mes3#ntlmtype3mes.lm_response,
        NTLM_hash = Mes3#ntlmtype3mes.ntlm_response,
       case esmb:user_logon(S, Neg, U, LM_hash, NTLM_hash) of
        ?IS_ERROR(Pdu0) ->
            Emsg = ?EMSG(Pdu0),
            ?DEBUG("cyrsasl_ntlm: SMB:Logon error: ~p",[Emsg]),
            esmb:close(S),
            {error, not_authorized, User};
        ?IS_OK(Pdu0) ->
            ?DEBUG("cyrsasl_ntlm: SMB:Logon user ~s into domain ~s ok.",[User,Domain]),
            esmb:close(S),
            {ok, [{username, User}, {authzid, User},
                  {auth_module, State#state.auth_module}]}
        end;
    _ ->
        ?DEBUG("cyrsasl_ntlm: NTLM Message Type 3 Error!",[]),
        {error, unexpected_response}
    end;
mech_step(A, B) ->
    ?DEBUG("SASL DIGEST: A ~p B ~p", [A,B]),
    {error, unexpected_response}.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

enc_NTLMType2Mes(ClientIn) ->
   MesSignature = ClientIn#ntlmtype2mes.signature,
   MesType = ClientIn#ntlmtype2mes.message_type,
   MesFlags  = ClientIn#ntlmtype2mes.flags,
   MesChallenge = ClientIn#ntlmtype2mes.challenge,
   MesContext = ClientIn#ntlmtype2mes.context,
   if 
      ClientIn#ntlmtype2mes.target_name == undefined ->
           TargetNameSecBuf = 0,
       MesType2 = binary_to_list(<<MesSignature/bitstring, 
                                   MesType:32/little, 
                                   TargetNameSecBuf:64/little, 
                                   MesFlags:32/little, 
                                   MesChallenge/bitstring, 
                                   MesContext:64>>);
      true ->
       MesTargetName = ClientIn#ntlmtype2mes.target_name,
           TargetNameOffset = 40,
           TargetNameLength = byte_size(ClientIn#ntlmtype2mes.target_name),
           TargetNameSecBuf = <<TargetNameLength:16/little,TargetNameLength:16/little,TargetNameOffset:32/little>>,
       MesType2 = binary_to_list(<<MesSignature/bitstring, 
                                   MesType:32/little, 
                                   TargetNameSecBuf:64/bitstring, 
                                   MesFlags:32/little, 
                                   MesChallenge/bitstring, 
                                   MesContext:64,
                                   MesTargetName/bitstring>>)
   end,
   MesType2.

dec_NTLMType1Mes(ClientIn) ->
    MesSize = byte_size(ClientIn),
    if 
        MesSize == 16 ->
            <<SignatureData:64/bitstring, TypeMessData:2/little-signed-integer-unit:16, FlagsData:32/little, 
              RestClientIn/binary>> = ClientIn,
            RecType1Mes = #ntlmtype1mes{signature = SignatureData, message_type = TypeMessData, flags = FlagsData},
            if
                RecType1Mes#ntlmtype1mes.signature == ?NTLM_SIGNATURE ->
              if
                    RecType1Mes#ntlmtype1mes.message_type == ?NtLmNegotiate ->  
                            if 
                            (RecType1Mes#ntlmtype1mes.flags band ?FLAGS_Negotiate_NTLM) > 0 ->  
                            {ok, RecType1Mes};
                                true->
                            {error, unexpected_response}
                            end;
                true ->                      
                        {error, unexpected_response}
                  end;
                true ->
                  {error, unexpected_response}
            end;
        MesSize > 16 ->
            <<SignatureData:64/bitstring, TypeMessData:2/little-signed-integer-unit:16, FlagsData:32/little, 
              DomainBufLen:1/little-signed-integer-unit:16, DomainBufSpace:1/little-signed-integer-unit:16, DomainBufOffset:2/little-signed-integer-unit:16, 
              WorkstationBufLen:1/little-signed-integer-unit:16, WorkstationBufSpace:1/little-signed-integer-unit:16, WorkstationBufOffset:2/little-signed-integer-unit:16, 
              RestClientIn/binary>> = ClientIn,

            DomainDummyPartLen = DomainBufOffset*8,
            DomainBufSpaceBits = DomainBufSpace*8,
            WorkstationDummyPartLen = WorkstationBufOffset*8,
            WorkstationBufSpaceBits = WorkstationBufSpace*8,
    
            <<DomainDummy:DomainDummyPartLen/bitstring, DomainData:DomainBufSpaceBits/bitstring,RestDomainDummy/bitstring>> = list_to_bitstring(binary_to_list(ClientIn)),
            <<WorkstationDummy:WorkstationDummyPartLen/bitstring, WorkstationData:WorkstationBufSpaceBits/bitstring,RestWorkstationDummy/bitstring>> = list_to_bitstring(binary_to_list(ClientIn)),

            RecType1Mes = #ntlmtype1mes{signature = SignatureData, message_type = TypeMessData, flags = FlagsData, domain = DomainData, workstation = WorkstationData},
            if
                RecType1Mes#ntlmtype1mes.signature == ?NTLM_SIGNATURE ->
              if
                    RecType1Mes#ntlmtype1mes.message_type == ?NtLmNegotiate ->  
                            if 
                            (RecType1Mes#ntlmtype1mes.flags band ?FLAGS_Negotiate_NTLM) > 0 ->  
                            {ok, RecType1Mes};
                                true->
                            {error, unexpected_response}
                            end;
                true ->                      
                        {error, unexpected_response}
                  end;
                true ->
                  {error, unexpected_response}
            end;
        MesSize < 16 ->
            {error, unexpected_response}
    end.
    
dec_NTLMType3Mes(ClientIn) ->
    MesSize = byte_size(ClientIn),
    if 
        MesSize >= 52 ->
            <<SignatureData:64/bitstring, TypeMessData:2/little-signed-integer-unit:16,
                      LMResponseBufLen:1/little-signed-integer-unit:16, 
                      LMResponseBufSpace:1/little-signed-integer-unit:16, 
                      LMResponseBufOffset:2/little-signed-integer-unit:16, 
                      NTLMResponseBufLen:1/little-signed-integer-unit:16, 
                      NTLMResponseBufSpace:1/little-signed-integer-unit:16, 
                      NTLMResponseBufOffset:2/little-signed-integer-unit:16, 
                      TargetNameBufLen:1/little-signed-integer-unit:16, 
                      TargetNameBufSpace:1/little-signed-integer-unit:16, 
                      TargetNameBufOffset:2/little-signed-integer-unit:16, 
                      UserNameBufLen:1/little-signed-integer-unit:16, 
                      UserNameBufSpace:1/little-signed-integer-unit:16, 
                      UserNameBufOffset:2/little-signed-integer-unit:16, 
                      WorkstationBufLen:1/little-signed-integer-unit:16, 
                      WorkstationBufSpace:1/little-signed-integer-unit:16, 
                      WorkstationBufOffset:2/little-signed-integer-unit:16, 
              RestClientIn/binary>> = ClientIn,

                    LMResponseDummyPartLen = LMResponseBufOffset*8,
                    LMResponseBufSpaceBits = LMResponseBufSpace*8,
                    NTLMResponseDummyPartLen = NTLMResponseBufOffset*8,
                    NTLMResponseBufSpaceBits = NTLMResponseBufSpace*8,
                    TargetNameDummyPartLen = TargetNameBufOffset*8,
                    TargetNameBufSpaceBits = TargetNameBufSpace*8,
                    UserNameDummyPartLen = UserNameBufOffset*8,
                    UserNameBufSpaceBits = UserNameBufSpace*8,
                    WorkstationDummyPartLen = WorkstationBufOffset*8,
                    WorkstationBufSpaceBits = WorkstationBufSpace*8,

                    <<LMResponseDummy:LMResponseDummyPartLen/bitstring, LMResponseData:LMResponseBufSpaceBits/bitstring,RestLMResponseDummy/bitstring>> = list_to_bitstring(binary_to_list(ClientIn)),
                    <<NTLMResponseDummy:NTLMResponseDummyPartLen/bitstring, NTLMResponseData:NTLMResponseBufSpaceBits/bitstring,RestNTLMResponseDummy/bitstring>> = list_to_bitstring(binary_to_list(ClientIn)),
                    <<TargetNameDummy:TargetNameDummyPartLen/bitstring, TargetNameData:TargetNameBufSpaceBits/bitstring,RestTargetNameDummy/bitstring>> = list_to_bitstring(binary_to_list(ClientIn)),
                    <<UserNameDummy:UserNameDummyPartLen/bitstring, UserNameData:UserNameBufSpaceBits/bitstring,RestUserNameDummy/bitstring>> = list_to_bitstring(binary_to_list(ClientIn)),
                    <<WorkstationDummy:WorkstationDummyPartLen/bitstring, WorkstationData:WorkstationBufSpaceBits/bitstring,RestWorkstationDummy/bitstring>> = list_to_bitstring(binary_to_list(ClientIn)),

                    StartDataBlock = lists:min([LMResponseBufOffset, NTLMResponseBufOffset ,TargetNameBufOffset , UserNameBufOffset, WorkstationBufOffset]),
                    if ((StartDataBlock - 52) >= 12) ->
                        <<SessionKeyBufDummy:416/bitstring, 
            SessionKeyBufLen:1/little-signed-integer-unit:16, 
            SessionKeyBufSpace:1/little-signed-integer-unit:16, 
            SessionKeyBufOffset:2/little-signed-integer-unit:16, 
            Flags:32/little, 
                    RestSessionKeyBufDummy/bitstring>> = list_to_bitstring(binary_to_list(ClientIn)),
    
            SessionKeyDummyPartLen = SessionKeyBufOffset*8,
            SessionKeyBufSpaceBits = SessionKeyBufSpace*8,

            <<SessionKeyDummy:SessionKeyDummyPartLen/bitstring, SessionKeyData:SessionKeyBufSpaceBits/bitstring,RestSessionKeyDummy/bitstring>> = list_to_bitstring(binary_to_list(ClientIn)),
                RecType3Mes = #ntlmtype3mes{signature = SignatureData, message_type = TypeMessData, 
                                            lm_response = LMResponseData, ntlm_response = NTLMResponseData,
                                            target_name = TargetNameData, user_name = UserNameData, 
                                            workstation_name = WorkstationData, session_key = SessionKeyData, flags = Flags};
                       true ->
                RecType3Mes = #ntlmtype3mes{signature = SignatureData, message_type = TypeMessData, 
                                            lm_response = LMResponseData, ntlm_response = NTLMResponseData,
                                            target_name = TargetNameData, user_name = UserNameData, 
                                            workstation_name = WorkstationData}
                    end,
            if
                RecType3Mes#ntlmtype3mes.signature == ?NTLM_SIGNATURE ->
              if
                    RecType3Mes#ntlmtype3mes.message_type == ?NtLmAuthenticate ->   
                        {ok, RecType3Mes};
                true ->                      
                        {error, unexpected_response}
                  end;
                true ->
                  {error, unexpected_response}
            end;
        MesSize < 52 ->
            {error, unexpected_response}
    end.

cset_to_ucs2(Str, Cset) ->
    Rstr = iconv:convert(esmb:ucase(Cset), ?CSET_UCS2LE, Str),
    Rstr.             

ucs2_to_cset(Str, Cset) ->
    Rstr = iconv:convert(?CSET_UCS2LE, esmb:ucase(Cset), Str),
    Rstr.             

%% Print Messages for each flag in NTLM message
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Unicode) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Unicode",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Unicode));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_OEM) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate OEM",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_OEM));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Request_Target) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Request Target",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Request_Target));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Sign) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Sign",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Sign));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Seal) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Seal",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Seal));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Datagram_Style) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Datagram Style",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Datagram_Style));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Lan_Manager_Key) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Lan Manager Key",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Lan_Manager_Key));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Netware) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Netware",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Netware));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_NTLM) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate NTLM",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_NTLM));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Anonymous) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Anonymous",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Anonymous));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Domain_Supplied) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Domain Supplied",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Domain_Supplied));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Workstation_Supplied) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Workstation Supplied",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Workstation_Supplied));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Local_Call) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Local Call",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Local_Call));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Always_Sign) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Always Sign",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Always_Sign));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Target_Type_Domain) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Target Type Domain",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Target_Type_Domain));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Target_Type_Server) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Target Type Server",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Target_Type_Server));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Target_Type_Share) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Target Type Share",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Target_Type_Share));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_NTLM2_Key) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate NTLM2 Key",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_NTLM2_Key));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Request_Init_Response) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Request Init Response",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Request_Init_Response));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Request_Accept_Response) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Request Accept Response",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Request_Accept_Response));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Request_Non_NT_Session_Key) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Request Non-NT Session Key",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Request_Non_NT_Session_Key));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Target_Info) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Target Info",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Target_Info));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_128) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate 128",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_128));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_Key_Exchange) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate Key Exchange",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_Key_Exchange));
echo_flags(FlagData) when ((FlagData band ?FLAGS_Negotiate_56) > 0) -> 
    ?DEBUG("cyrsasl_ntlm: NTLM flag: Negotiate 56",[]),
    echo_flags(FlagData band (bnot ?FLAGS_Negotiate_56));
echo_flags(_) -> 
%%    ?DEBUG("cyrsasl_ntlm: NTLM flag: End.",[]),
    ok.

opt_type(ntlmpdc) -> fun iolist_to_binary/1;
opt_type(_) -> [ntlmpdc].
