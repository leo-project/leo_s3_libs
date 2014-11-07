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
%% Leo S3 Libs - ETS/Mnesia Data Handler
%% @doc THe s3-libs data handler
%% @reference https://github.com/leo-project/leo_s3_libs/blob/master/src/leo_s3_libs_data_handler.erl
%% @end
%%======================================================================
-module(leo_s3_libs_data_handler).

-author('Yosuke Hara').

-include("leo_s3_auth.hrl").
-include_lib("stdlib/include/qlc.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/1, lookup/2, insert/2, delete/2, size/1]).


%% Retrieve all records from the table.
%%
-spec(all(DBInfo) ->
             {ok, [_]} | not_found | {error, any()} when DBInfo::{mnesia|ets, atom()}).
all({mnesia, Table}) ->
    case catch mnesia:ets(fun ets:tab2list/1, [Table]) of
        {'EXIT', Cause} ->
            {error, Cause};
        [] ->
            not_found;
        List ->
            {ok, lists:sort(List)}
    end;
all({ets, Table}) ->
    case catch ets:tab2list(Table) of
        {'EXIT', Cause} ->
            {error, Cause};
        [] ->
            not_found;
        List ->
            List_1 = lists:map(fun({_, Item}) ->
                                       Item
                               end, List),
            {ok, lists:sort(List_1)}
    end.


%% Retrieve a record by key from the table.
%%
-spec(lookup(DBInfo, Id) ->
             {ok, any()} | not_found | {error, any()} when DBInfo::{mnesia|ets, atom()},
                                                           Id::any()).
lookup({mnesia, Table}, Id) ->
    case catch mnesia:ets(fun ets:lookup/2, [Table, Id]) of
        [Value|_] ->
            {ok, Value};
        [] ->
            not_found;
        {'EXIT', Cause} ->
            {error, Cause}
    end;
lookup({ets, Table}, Id) ->
    case catch ets:lookup(Table, Id) of
        [{_,Value}|_] ->
            {ok, Value};
        [] ->
            not_found;
        {'EXIT', Cause} ->
            {error, Cause}
    end.


%% @doc Insert a record into the table.
%%
-spec(insert(DBInfo, {Id, Value}) ->
             ok | {error, any()} when DBInfo::{mnesia|ets, atom()},
                                      Id::any(),
                                      Value::any()).
insert({mnesia, Table}, {_Id, Value}) ->
    Fun = fun() -> mnesia:write(Table, Value, write) end,
    leo_mnesia:write(Fun);

insert({ets, Table}, {Id, Value}) ->
    case ets:insert(Table, {Id, Value}) of
        true ->
            ok
    end.



%% @doc Remove a record from the table.
%%
-spec(delete(DBInfo, Id) ->
             ok | {error, any()} when DBInfo::{mnesia|ets, atom()},
                                      Id::any()).
delete({mnesia, Table}, Id) ->
    case lookup({mnesia, Table}, Id) of
        {ok, Value} ->
            Fun = fun() ->
                          mnesia:delete_object(Table, Value, write)
                  end,
            leo_mnesia:delete(Fun);
        not_found = Cause ->
            {error, Cause};
        Error ->
            Error
    end;
delete({ets, Table}, Id) ->
    case ets:delete(Table, Id) of
        true ->
            ok
    end.


%% @doc Retrieve total of records.
%%
-spec(size(DBInfo) ->
      integer() when DBInfo::{mnesia|ets, atom()}).
size({mnesia, Table}) ->
    mnesia:ets(fun ets:info/2, [Table, size]);
size({ets, Table}) ->
    ets:info(Table, size).

