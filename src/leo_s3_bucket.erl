%%======================================================================
%%
%% Leo S3-Libs
%%
%% Copyright (c) 2012 Rakuten, Inc.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% ---------------------------------------------------------------------
%% Leo Libs - Bucket
%% @doc
%% @end
%%======================================================================
-module(leo_s3_bucket).

-author('Yosuke Hara').

-include("leo_s3_bucket.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([start/2, create_bucket_table/2,
         find_buckets_by_id/1, find_buckets_by_id/2, find_all/0,
         put/2, put/3, delete/2, head/2, head/4]).

-define(BUCKET_DB_TYPE,   leo_s3_bucket_db).
-define(BUCKET_DB_EXPIRE, 300).  %% default expire time is 5min
-define(BUCKET_INFO,      leo_s3_bucket_info).
-define(BUCKET_TABLE,     buckets).
-define(DEF_REQ_TIMEOUT,  30000).

-ifdef(EUNIT).
-define(NOW, 0).
-else.
-define(NOW, leo_utils:now()).
-endif.

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
%% @doc
%%
-spec(start(atom(), ets | mnesia) ->
             ok).
start(slave = Type, Provider) ->
    ?BUCKET_TABLE = ets:new(?BUCKET_TABLE, [named_table, ordered_set, public, {read_concurrency, true}]),
    ok = setup(Type, ets, Provider),
    ok;

start(master = Type, _Options) ->
    ok = setup(Type, mnesia, []),
    ok.


setup(Type, DB, Provider) ->
    ?BUCKET_INFO  = ets:new(?BUCKET_INFO,  [named_table, set, public, {read_concurrency, true}]),
    true = ets:insert(?BUCKET_INFO, {1, #bucket_info{type = Type,
                                                     db   = DB,
                                                     provider = Provider}}),
    ok.


%% Create bucket table(mnesia)
%%
create_bucket_table(Mode, Nodes) ->
    _ = application:start(mnesia),
    {atomic, ok} =
        mnesia:create_table(
          ?BUCKET_TABLE,
          [{Mode, Nodes},
           {type, set},
           {record_name, bucket},
           {attributes, record_info(fields, bucket)},
           {user_properties,
            [{name,       {varchar, undefined}, false, primary,   undefined, identity,  varchar},
             {access_key, {varchar, undefined}, false, undefined, undefined, undefined, varchar},
             {created_at, {integer, undefined}, false, undefined, undefined, undefined, integer}
            ]}
          ]),
    ok.


%% @doc Retrieve buckets by AccessKey
%%
-spec(find_buckets_by_id(string()) ->
             {ok, list()} | {error, any()}).
find_buckets_by_id(AccessKey) ->
    case get_info() of
        %% Retrieve value from local-mnesia.
        {ok, #bucket_info{db = DB}} when DB == mnesia ->
            leo_s3_bucket_data_handler:lookup({DB, ?BUCKET_TABLE}, AccessKey);

        %% Inquiry bucket-checksum to manager-nodes.
        %% If local-checksum equal provider's checksum, then return local-list,
        %% but local-checksum does NOT equal provider's checksum, then return provider's list.
        {ok, #bucket_info{db = DB, provider = Provider}} when DB == ets ->
            find_buckets_by_id_1(AccessKey, DB, Provider);
        Error ->
            Error
    end.

-spec(find_buckets_by_id(string(), string()) ->
             {ok, list()} | {ok, match} | {error, any()}).
find_buckets_by_id(AccessKey, Checksum0) ->
    case get_info() of
        {ok, #bucket_info{db = DB}} when DB == mnesia ->
            case find_buckets_by_id(AccessKey) of
                {ok, Value} ->
                    case erlang:crc32(term_to_binary(Value)) of
                        Checksum0 ->
                            {ok, match};
                        _ ->
                            {ok, Value}
                    end;
                Error ->
                    Error
            end;
        {ok, #bucket_info{db = DB}} when DB == ets ->
            {error, ignored};
        Error ->
            Error
    end.


%% @doc Retrieve all buckets
%%
-spec(find_all() ->
             {ok, list()} | {error, any()}).
find_all() ->
    case get_info() of
        {ok, #bucket_info{db = DB}} ->
            leo_s3_bucket_data_handler:find_all({DB, ?BUCKET_TABLE});
        Error ->
            Error
    end.


%% @doc put a bucket.
%%
-spec(put(string(), string()) ->
             ok | {error, any()}).
put(AccessKey, Bucket) ->
    case get_info() of
        {ok, #bucket_info{type = slave,
                          db   = DB,
                          provider = Provider}} ->
            ?debugVal(Provider),
            case rpc_call(Provider, put, AccessKey, Bucket) of
                true  -> put(AccessKey, Bucket, DB);
                false -> {error, not_stored}
            end;
        {ok, #bucket_info{type = master, db = DB}} ->
            ?debugVal(ok),
            put(AccessKey, Bucket, DB);
        Error ->
            Error
    end.

-spec(put(string(), string(), ets | mnesia) ->
             ok | {error, any()}).
put(AccessKey, Bucket, DB) ->
    leo_s3_bucket_data_handler:insert({DB, ?BUCKET_TABLE},
                                      #bucket{name       = Bucket,
                                              access_key = AccessKey,
                                              created_at = ?NOW
                                             }).


%% @doc delete a bucket.
%%
-spec(delete(string(), string()) ->
             ok | {error, any()}).
delete(AccessKey, Bucket) ->
    case get_info() of
        {ok, #bucket_info{type = slave,
                          db   = DB,
                          provider = Provider}} ->
            case rpc_call(Provider, delete, AccessKey, Bucket) of
                true  -> delete(AccessKey, Bucket, DB);
                false -> {error, not_deleted}
            end;
        {ok, #bucket_info{type = master, db = DB}} ->
            delete(AccessKey, Bucket, DB);
        Error ->
            Error
    end.


-spec(delete(string(), string(), ets | mnesia) ->
             ok | {error, any()}).
delete(AccessKey, Bucket, DB) ->
    leo_s3_bucket_data_handler:delete({DB, ?BUCKET_TABLE},
                                      #bucket{name = Bucket,
                                              access_key = AccessKey}).


%% @doc Is exist a bucket into the db
%%
-spec(head(string(), string()) ->
             ok | not_found | {error, forbidden} | {error, any()}).
head(AccessKey, Bucket) ->
    case get_info() of
        {ok, #bucket_info{db       = DB,
                          type     = Type,
                          provider = Provider}} ->
            case leo_s3_bucket_data_handler:find_by_name(
                   {DB, ?BUCKET_TABLE}, AccessKey, Bucket) of
                {ok, _Value0} ->
                    ok;
                not_found when Type == slave->
                    case head(AccessKey, Bucket, DB, Provider) of
                        {ok, _} ->
                            ok;
                        Error ->
                            Error
                    end;
                Other ->
                    Other
            end;
        Error ->
            Error
    end.

head(AccessKey, Bucket, DB, Provider) ->
    case find_buckets_by_id_1(AccessKey, DB, Provider) of
        {ok, _} ->
            Ret = leo_s3_bucket_data_handler:find_by_name(
                    {DB, ?BUCKET_TABLE}, AccessKey, Bucket),
            Ret;
        Error ->
            Error
    end.


%%--------------------------------------------------------------------
%% INNER FUNCTIONS
%%--------------------------------------------------------------------
%% @doc Retrieve database-type.
%% @private
-spec(get_info() ->
             {ok, #bucket{}} | {error, any()}).
get_info() ->
    case ets:lookup(?BUCKET_INFO, 1) of
        [{_, Info}|_] ->
            {ok, Info};
        [] ->
            {error, not_initialized};
        {_, Cause} ->
            {error, Cause}
    end.


%% @doc Insert values into the mnesia.
%%
-spec(put_all_values(ets | mnesia, list()) ->
             ok).
put_all_values(_, []) ->
    ok;
put_all_values(DB, [H|T]) ->
    leo_s3_bucket_data_handler:insert({DB, ?BUCKET_TABLE}, H),
    put_all_values(DB, T).


find_buckets_by_id_1(AccessKey, DB, Providers) ->
    {Value0, CRC} = case leo_s3_bucket_data_handler:lookup(
                           {DB, ?BUCKET_TABLE}, AccessKey) of
                        {ok, Val} ->
                            {Val, erlang:crc32(term_to_binary(Val))};
                        _Other ->
                            {[], -1}
                    end,

    Ret = lists:foldl(
            fun(Node, []) ->
                    find_buckets_by_id_2(AccessKey, DB, Node, Value0, CRC);
               (Node, {error, _Cause}) ->
                    find_buckets_by_id_2(AccessKey, DB, Node, Value0, CRC);
               (_Node, Acc) ->
                    Acc
            end, [], Providers),
    Ret.

find_buckets_by_id_2(AccessKey, DB, Node, Value0, CRC) ->
    RPCKey = rpc:async_call(Node, leo_s3_bucket, find_buckets_by_id,
                            [AccessKey, CRC]),
    Ret = case rpc:nb_yield(RPCKey, ?DEF_REQ_TIMEOUT) of
              {value, {ok, match}} when Value0 == [] ->
                  not_found;
              {value, {ok, match}} when Value0 /= [] ->
                  {ok, Value0};
              {value, {ok, Value1}} ->
                  lists:foreach(fun(Bucket) ->
                                        leo_s3_bucket_data_handler:delete({DB, ?BUCKET_TABLE}, Bucket)
                                end, Value0),
                  ok = put_all_values(ets, Value1),
                  {ok, Value1};
              {value, not_found} ->
                  not_found;
              {value, {error, Cause}} ->
                  {error, Cause};
              {badrpc, Cause} ->
                  {error, Cause};
              {'EXIT', Cause} ->
                  {error, Cause}
          end,
    Ret.


%% @doc
%%
-spec(rpc_call(list(), atom(), string(), string()) ->
             true | false).
rpc_call(Provider, Function, AccessKey, Bucket) ->
    Ret = lists:foldl(
            fun(Node, false) ->
                    RPCKey = rpc:async_call(Node, leo_s3_bucket, Function, [AccessKey, Bucket]),
                    case rpc:nb_yield(RPCKey, ?DEF_REQ_TIMEOUT) of
                        {value, ok} -> true;
                        _Error      -> false
                    end;
               (_, true) ->
                    true
            end, false, Provider),
    Ret.

