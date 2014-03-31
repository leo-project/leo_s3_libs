%%======================================================================
%%
%% Leo S3-Libs
%%
%% Copyright (c) 2012-2014 Rakuten, Inc.
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
%% Leo S3 Libs - EndPoint
%% @doc
%% @end
%%======================================================================
-module(leo_s3_endpoint).

-author('Yosuke Hara').

-include("leo_s3_endpoint.hrl").
-include("leo_s3_libs.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([start/2,  create_table/2,
         update_providers/1,
         set_endpoint/1, get_endpoints/0, delete_endpoint/1,
         checksum/0
        ]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
%% @doc Launch or create  Mnesia/ETS
%%
-spec(start(master | slave, list()) ->
             ok).
start(slave = Type, Provider) ->
    catch ets:new(?ENDPOINT_TABLE, [named_table, set,         public, {read_concurrency, true}]),
    catch ets:new(?ENDPOINT_INFO,  [named_table, ordered_set, public, {read_concurrency, true}]),

    case Provider of
        [] ->
            void;
        _ ->
            ok = setup(Type, ets, Provider)
    end,
    ok;

start(master = Type,_Provider) ->
    catch ets:new(?ENDPOINT_INFO,  [named_table, ordered_set, public, {read_concurrency, true}]),
    ok = setup(Type, mnesia, []),
    ok.

%% @doc update_providers(slave only)
%%
-spec(update_providers(list()) ->
             ok).
update_providers(Provider) ->
    true = ets:insert(?ENDPOINT_INFO, {1, #endpoint_info{type = slave,
                                                         db   = ets,
                                                         provider = Provider}}),
    ok.

%% @doc Create endpoint table(mnesia)
%%
create_table(Mode, Nodes) ->
    catch application:start(mnesia),
    {atomic, ok} =
        mnesia:create_table(
          ?ENDPOINT_TABLE,
          [{Mode, Nodes},
           {type, set},
           {record_name, endpoint},
           {attributes, record_info(fields, endpoint)},
           {user_properties,
            [{endpoint,   string,  primary},
             {created_at, integer, false}
            ]}
          ]),
    ok.


%% @doc Insert a End-Point into the Mnesia or ETS
%%
-spec(set_endpoint(binary()) ->
             ok | {error, any()}).
set_endpoint(EndPoint) ->
    case get_endpoint_info() of
        {ok, #endpoint_info{db = DB}} ->
            ok = leo_s3_libs_data_handler:insert(
                   {DB, ?ENDPOINT_TABLE}, {EndPoint, #endpoint{endpoint   = EndPoint,
                                                               created_at = leo_date:now()}}),
            ok;
        Error ->
            Error
    end.


%% @doc Retrieve a End-Point from the Mnesia or ETS
%%
-spec(get_endpoints() ->
             {ok, list()} | {error, any()}).
get_endpoints() ->
    case get_endpoint_info() of
        {ok, #endpoint_info{db = DB,
                            provider = Provider}} ->
            get_endpoints_1(DB, Provider);
        Error ->
            Error
    end.


%% @doc Remove a End-Point from the Mnesia or ETS
%%
-spec(delete_endpoint(binary()) ->
             ok | {error, any()}).
delete_endpoint(EndPoint) ->
    case get_endpoint_info() of
        {ok, #endpoint_info{db = DB}} ->
            leo_s3_libs_data_handler:delete({DB, ?ENDPOINT_TABLE}, EndPoint);
        Error ->
            Error
    end.


%% @doc Retrieve checksum of the table
-spec(checksum() ->
             {ok, pos_integer()} | not_found | {error, any()}).
checksum() ->
    case leo_s3_libs_data_handler:all({mnesia, ?ENDPOINT_TABLE}) of
        {ok, RetL} ->
            {ok, erlang:crc32(term_to_binary(RetL))};
        Error ->
            Error
    end.


%%--------------------------------------------------------------------
%% INNER FUNCTION
%%--------------------------------------------------------------------
%% @doc Setup
%% @private
setup(Type, DB, Provider) ->
    true = ets:insert(?ENDPOINT_INFO, {1, #endpoint_info{type = Type,
                                                         db   = DB,
                                                         provider = Provider}}),
    ok.


%% @doc Retrieve EndPoints from Mnesia/ETS
%% @private
get_endpoints_1(DB, Provider) ->
    case leo_s3_libs_data_handler:all({DB, ?ENDPOINT_TABLE}) of
        {ok, EndPoints} ->
            {ok, EndPoints};
        not_found when DB == ets->
            get_endpoints_2(DB, Provider);
        Error ->
            Error
    end.

%% @doc Retrieve EndPoints from Remote Node
%% @private
get_endpoints_2(DB, Provider) ->
    case lists:foldl(
           fun(Node, [] = Acc) ->
                   RPCKey = rpc:async_call(Node, leo_s3_endpoint, get_endpoints, []),
                   case rpc:nb_yield(RPCKey, ?DEF_REQ_TIMEOUT) of
                       {value, {ok, Value}} -> Value;
                       _ -> Acc
                   end;
              (_Node, Acc) ->
                   Acc
           end, [], Provider) of
        [] ->
            {error, not_found};
        EndPoints ->
            lists:foreach(fun(Item) ->
                                  _ = leo_s3_libs_data_handler:insert(
                                        {DB, ?ENDPOINT_TABLE}, {Item#endpoint.endpoint, Item})
                          end, EndPoints),
            {ok, EndPoints}
    end.

%% @doc Retrieve endpoint info from ETS
%% @private
-spec(get_endpoint_info() ->
             {ok, list()} | not_fonund).
get_endpoint_info() ->
    case catch ets:lookup(?ENDPOINT_INFO, 1) of
        [{_, EndPointInfo}|_] ->
            {ok, EndPointInfo};
        _ ->
            not_found
    end.

