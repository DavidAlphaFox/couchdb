%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

%% -*- erlang-indent-level: 4;indent-tabs-mode: nil -*-

-module(nouveau_api).

-include("nouveau.hrl").

-export([
    analyze/2,
    index_info/1,
    create_index/2,
    delete_path/1,
    delete_path/2,
    delete_doc/4,
    purge_doc/4,
    update_doc/6,
    search/2,
    set_purge_seq/3,
    set_update_seq/3,
    jaxrs_error/2
]).

-define(JSON_CONTENT_TYPE, {"Content-Type", "application/json"}).

analyze(Text, Analyzer) when
    is_binary(Text), is_binary(Analyzer)
->
    ReqBody = {[{<<"text">>, Text}, {<<"analyzer">>, Analyzer}]},
    Resp = send_if_enabled(
        "/analyze",
        [?JSON_CONTENT_TYPE],
        <<"POST">>,
        jiffy:encode(ReqBody)
    ),
    case Resp of
        {ok, 200, _, RespBody} ->
            Json = jiffy:decode(RespBody, [return_maps]),
            {ok, maps:get(<<"tokens">>, Json)};
        {ok, StatusCode, _, RespBody} ->
            {error, jaxrs_error(StatusCode, RespBody)};
        {error, Reason} ->
            send_error(Reason)
    end;
analyze(_, _) ->
    {error, {bad_request, <<"'text' and 'analyzer' fields must be non-empty strings">>}}.

index_info(#index{} = Index) ->
    Resp = send_if_enabled(index_path(Index), [], <<"GET">>),
    case Resp of
        {ok, 200, _, RespBody} ->
            {ok, jiffy:decode(RespBody, [return_maps])};
        {ok, StatusCode, _, RespBody} ->
            {error, jaxrs_error(StatusCode, RespBody)};
        {error, Reason} ->
            send_error(Reason)
    end.

create_index(#index{} = Index, IndexDefinition) ->
    Resp = send_if_enabled(
        index_path(Index), [?JSON_CONTENT_TYPE], <<"PUT">>, jiffy:encode(IndexDefinition)
    ),
    case Resp of
        {ok, 204, _, _} ->
            ok;
        {ok, StatusCode, _, RespBody} ->
            {error, jaxrs_error(StatusCode, RespBody)};
        {error, Reason} ->
            send_error(Reason)
    end.

delete_path(Path) ->
    delete_path(Path, []).

delete_path(Path, Exclusions) when
    is_binary(Path), is_list(Exclusions)
->
    Resp = send_if_enabled(
        index_path(Path), [?JSON_CONTENT_TYPE], <<"DELETE">>, jiffy:encode(Exclusions)
    ),
    case Resp of
        {ok, 204, _, _} ->
            ok;
        {ok, StatusCode, _, RespBody} ->
            {error, jaxrs_error(StatusCode, RespBody)};
        {error, Reason} ->
            send_error(Reason)
    end.

delete_doc(#index{} = Index, DocId, MatchSeq, UpdateSeq) when
    is_binary(DocId),
    is_integer(MatchSeq),
    MatchSeq >= 0,
    is_integer(UpdateSeq),
    UpdateSeq > 0
->
    ReqBody = #{match_seq => MatchSeq, seq => UpdateSeq, purge => false},
    send_if_enabled(
        doc_path(Index, DocId),
        [?JSON_CONTENT_TYPE],
        <<"DELETE">>,
        jiffy:encode(ReqBody)
    ).

purge_doc(#index{} = Index, DocId, MatchSeq, PurgeSeq) when
    is_binary(DocId),
    is_integer(MatchSeq),
    MatchSeq >= 0,
    is_integer(PurgeSeq),
    PurgeSeq > 0
->
    ReqBody = #{match_seq => MatchSeq, seq => PurgeSeq, purge => true},
    Resp = send_if_enabled(
        doc_path(Index, DocId), [?JSON_CONTENT_TYPE], <<"DELETE">>, jiffy:encode(ReqBody)
    ),
    case Resp of
        {ok, 204, _, _} ->
            ok;
        {ok, StatusCode, _, RespBody} ->
            {error, jaxrs_error(StatusCode, RespBody)};
        {error, Reason} ->
            send_error(Reason)
    end.

update_doc(#index{} = Index, DocId, MatchSeq, UpdateSeq, Partition, Fields) when
    is_binary(DocId),
    is_integer(MatchSeq),
    MatchSeq >= 0,
    is_integer(UpdateSeq),
    UpdateSeq > 0,
    (is_binary(Partition) orelse Partition == null),
    is_list(Fields)
->
    ReqBody = #{
        match_seq => MatchSeq,
        seq => UpdateSeq,
        partition => Partition,
        fields => Fields
    },
    send_if_enabled(
        doc_path(Index, DocId),
        [?JSON_CONTENT_TYPE],
        <<"PUT">>,
        jiffy:encode(ReqBody)
    ).

search(#index{} = Index, QueryArgs) ->
    Resp = send_if_enabled(
        search_path(Index), [?JSON_CONTENT_TYPE], <<"POST">>, jiffy:encode(QueryArgs)
    ),
    case Resp of
        {ok, 200, _, RespBody} ->
            {ok, jiffy:decode(RespBody, [return_maps])};
        {ok, 409, _, _} ->
            %% Index was not current enough.
            {error, stale_index};
        {ok, StatusCode, _, RespBody} ->
            {error, jaxrs_error(StatusCode, RespBody)};
        {error, Reason} ->
            send_error(Reason)
    end.

set_update_seq(#index{} = Index, MatchSeq, UpdateSeq) ->
    ReqBody = #{
        match_update_seq => MatchSeq,
        update_seq => UpdateSeq
    },
    set_seq(Index, ReqBody).

set_purge_seq(#index{} = Index, MatchSeq, PurgeSeq) ->
    ReqBody = #{
        match_purge_seq => MatchSeq,
        purge_seq => PurgeSeq
    },
    set_seq(Index, ReqBody).

set_seq(#index{} = Index, ReqBody) ->
    Resp = send_if_enabled(
        index_path(Index), [?JSON_CONTENT_TYPE], <<"POST">>, jiffy:encode(ReqBody)
    ),
    case Resp of
        {ok, 204, _, _} ->
            ok;
        {ok, StatusCode, _, RespBody} ->
            {error, jaxrs_error(StatusCode, RespBody)};
        {error, Reason} ->
            send_error(Reason)
    end.

%% private functions

index_path(Path) when is_binary(Path) ->
    lists:flatten(
        io_lib:format(
            "/index/~s",
            [
                couch_util:url_encode(Path)
            ]
        )
    );
index_path(#index{} = Index) ->
    lists:flatten(
        io_lib:format(
            "/index/~s",
            [
                couch_util:url_encode(nouveau_util:index_name(Index))
            ]
        )
    ).

doc_path(#index{} = Index, DocId) ->
    lists:flatten(
        io_lib:format(
            "/index/~s/doc/~s",
            [
                couch_util:url_encode(nouveau_util:index_name(Index)),
                couch_util:url_encode(DocId)
            ]
        )
    ).

search_path(IndexName) ->
    index_path(IndexName) ++ "/search".

jaxrs_error(400, Body) ->
    {bad_request, message(Body)};
jaxrs_error(404, Body) ->
    {not_found, message(Body)};
jaxrs_error(405, Body) ->
    {method_not_allowed, message(Body)};
jaxrs_error(409, Body) ->
    {conflict, message(Body)};
jaxrs_error(417, Body) ->
    {expectation_failed, message(Body)};
jaxrs_error(422, Body) ->
    {bad_request, lists:join(" and ", errors(Body))};
jaxrs_error(500, Body) ->
    {internal_server_error, message(Body)}.

send_error({conn_failed, _}) ->
    {error, {service_unavailable, <<"Search service unavailable.">>}};
send_error(Reason) ->
    {error, Reason}.

message(Body) ->
    Json = jiffy:decode(Body, [return_maps]),
    maps:get(<<"message">>, Json).

errors(Body) ->
    Json = jiffy:decode(Body, [return_maps]),
    maps:get(<<"errors">>, Json).

send_if_enabled(Path, ReqHeaders, Method) ->
    send_if_enabled(Path, ReqHeaders, Method, <<>>).

send_if_enabled(Path, ReqHeaders, Method, ReqBody) ->
    case nouveau:enabled() of
        true ->
            retry_if_connection_closes(fun() ->
                {async, PoolStreamRef} = gun_pool:request(
                    Method, Path, [host_header() | ReqHeaders], ReqBody
                ),
                case gun_pool:await(PoolStreamRef) of
                    {response, fin, Status, RespHeaders} ->
                        {ok, Status, RespHeaders, []};
                    {response, nofin, Status, RespHeaders} ->
                        {ok, RespBody} = gun_pool:await_body(PoolStreamRef),
                        {ok, Status, RespHeaders, RespBody}
                end
            end);
        false ->
            {error, nouveau_not_enabled}
    end.

retry_if_connection_closes(Fun) ->
    MaxRetries = max(1, config:get_integer("nouveau", "max_retries", 5)),
    retry_if_connection_closes(Fun, MaxRetries).

retry_if_connection_closes(_Fun, 0) ->
    {error, connection_closed};
retry_if_connection_closes(Fun, N) when is_integer(N), N > 0 ->
    case Fun() of
        {error, connection_closed} ->
            couch_stats:increment_counter([nouveau, connection_closed_errors]),
            timer:sleep(1000),
            retry_if_connection_closes(Fun, N - 1);
        Else ->
            Else
    end.

host_header() ->
    #{host := Host, port := Port} = uri_string:parse(nouveau_util:nouveau_url()),
    {<<"host">>, [Host, $:, integer_to_binary(Port)]}.
