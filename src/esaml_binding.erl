%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc SAML HTTP binding handlers
-module(esaml_binding).

-export([decode_response/2, encode_http_redirect/4, encode_http_post/3, encode_http_post/4]).

-include_lib("xmerl/include/xmerl.hrl").
-define(deflate, <<"urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE">>).
-define(MAX_INFLATED_BYTES, 1000000).

-type uri() :: binary() | string().
-type html_doc() :: binary().
-type xml() :: #xmlElement{} | #xmlDocument{}.

%% @private
-spec xml_payload_type(xml()) -> binary().
xml_payload_type(Xml) ->
    case Xml of
        #xmlDocument{content = [#xmlElement{name = Atom}]} ->
            case lists:suffix("Response", atom_to_list(Atom)) of
                true -> <<"SAMLResponse">>;
                _ -> <<"SAMLRequest">>
            end;
        #xmlElement{name = Atom} ->
            case lists:suffix("Response", atom_to_list(Atom)) of
                true -> <<"SAMLResponse">>;
                _ -> <<"SAMLRequest">>
            end;
        _ -> <<"SAMLRequest">>
    end.

%% @doc Unpack and parse a SAMLResponse with given encoding
-spec decode_response(SAMLEncoding :: binary(), SAMLResponse :: binary() | string()) -> #xmlElement{}.
decode_response(?deflate, SAMLResponse) ->
	XmlData = binary_to_list(inflate(base64:decode(SAMLResponse))),
	Xml = esaml_util:parse_xml(XmlData),
    Xml;
decode_response(_, SAMLResponse) ->
	Data = base64:decode(SAMLResponse),
    XmlData = try inflate(Data) of
        Bin -> binary_to_list(Bin)
    catch
        error:data_error -> binary_to_list(Data)
    end,
	Xml = esaml_util:parse_xml(XmlData),
    Xml.

%% @private
%% Inflates raw DEFLATE data, as zlib:unzip/1 does, but stops at ?MAX_INFLATED_BYTES.
%% Data that is not deflated raises data_error.
-spec inflate(binary()) -> binary().
inflate(Data) ->
    Z = zlib:open(),
    try
        ok = zlib:inflateInit(Z, -15),
        inflate_chunks(Z, zlib:safeInflate(Z, Data), [], 0)
    after
        zlib:close(Z)
    end.

inflate_chunks(Z, {Status, Chunk}, Chunks, Size0) ->
    Size = Size0 + iolist_size(Chunk),
    if
        Size > ?MAX_INFLATED_BYTES ->
            error({inflated_response_too_large, ?MAX_INFLATED_BYTES});
        Status =:= continue ->
            inflate_chunks(Z, zlib:safeInflate(Z, []), [Chunks, Chunk], Size);
        Status =:= finished ->
            ok = zlib:inflateEnd(Z),
            iolist_to_binary([Chunks, Chunk])
    end.

%% @doc Encode a SAMLRequest (or SAMLResponse) as an HTTP-Redirect binding
%%
%% Returns the URI that should be the target of redirection.
-spec encode_http_redirect(IDPTarget :: uri(), SignedXml :: xml(), Username :: undefined | string(), RelayState :: binary()) -> uri().
encode_http_redirect(IdpTarget, SignedXml, Username, RelayState) ->
  Type = xml_payload_type(SignedXml),
  Req = lists:flatten(xmerl:export([SignedXml], xmerl_xml)),

  QueryList = [
               {"SAMLEncoding", ?deflate},
               {Type, base64:encode_to_string(zlib:zip(Req))},
               {"RelayState", uri_string:normalize(binary_to_list(RelayState))}
              ],
  QueryParamStr = uri_string:compose_query(QueryList),
  FirstParamDelimiter = case lists:member($?, IdpTarget) of true -> "&"; false -> "?" end,
  Username_Part = redirect_username_part(Username),

  iolist_to_binary([IdpTarget, FirstParamDelimiter, QueryParamStr | Username_Part]).

redirect_username_part(Username) when is_binary(Username), size(Username) > 0 ->
  ["&", uri_string:compose_query([{"username", uri_string:normalize(binary_to_list(Username))}])];
redirect_username_part(_Other) -> [].

%% @doc Encode a SAMLRequest (or SAMLResponse) as an HTTP-POST binding
%%
%% Returns the HTML document to be sent to the browser, containing a
%% form and javascript to automatically submit it.
-spec encode_http_post(IDPTarget :: uri(), SignedXml :: xml(), RelayState :: binary()) -> html_doc().
encode_http_post(IdpTarget, SignedXml, RelayState) ->
    encode_http_post(IdpTarget, SignedXml, RelayState, <<>>).

-spec encode_http_post(IDPTarget :: uri(), SignedXml :: xml(), RelayState :: binary(), Nonce :: binary()) -> html_doc().
encode_http_post(IdpTarget, SignedXml, RelayState, Nonce) when is_binary(Nonce) ->
    Type = xml_payload_type(SignedXml),
	Req = lists:flatten(xmerl:export([SignedXml], xmerl_xml)),
    generate_post_html(Type, IdpTarget, base64:encode(Req), RelayState, Nonce).

generate_post_html(Type, Dest, Req, RelayState, Nonce) ->
    NonceFragment = case Nonce of
        <<>> -> <<>>;
        _ -> [<<"nonce=\"">>, Nonce, <<"\"">>]
    end,
    iolist_to_binary([<<"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">
<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">
<head>
<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" />
<title>POST data</title>
</head>
<body>
<script ">>,NonceFragment,<<">
document.addEventListener('DOMContentLoaded', function () {
document.getElementById('saml-req-form').submit();
});
</script>
<noscript>
<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>
</noscript>
<form id=\"saml-req-form\" method=\"post\" action=\"">>,Dest,<<"\">
<input type=\"hidden\" name=\"">>,Type,<<"\" value=\"">>,Req,<<"\" />
<input type=\"hidden\" name=\"RelayState\" value=\"">>,RelayState,<<"\" />
<noscript><input type=\"submit\" value=\"Submit\" /></noscript>
</form>
</body>
</html>">>]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-define(EXTERNAL_DTD_XML, <<"<!DOCTYPE x SYSTEM \"/dev/null\"><x/>">>).

decode_deflated_response_external_dtd_test() ->
    Response = base64:encode(zlib:zip(?EXTERNAL_DTD_XML)),
    ?assertExit({fatal, {{error_fetching_DTD, _}, _, _, _}}, decode_response(?deflate, Response)).

decode_response_external_dtd_test() ->
    Response = base64:encode(?EXTERNAL_DTD_XML),
    ?assertExit({fatal, {{error_fetching_DTD, _}, _, _, _}}, decode_response(<<>>, Response)).

decode_response_not_deflated_test() ->
    Response = base64:encode(<<"<x/>">>),
    ?assertMatch(#xmlElement{name = x}, decode_response(<<>>, Response)).

decode_response_too_large_test() ->
    Response = base64:encode(zlib:zip(binary:copy(<<" ">>, 2000000))),
    ?assertError({inflated_response_too_large, _}, decode_response(?deflate, Response)),
    ?assertError({inflated_response_too_large, _}, decode_response(<<>>, Response)).

-endif.
