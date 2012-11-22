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
%% Leo S3 Libs - Bucket - ETS/Mnesia Data Handler
%% @doc
%% @end
%%======================================================================
-module(leo_s3_bucket_data_handler).

-author('Yosuke Hara').

-include("leo_s3_bucket.hrl").
-include_lib("stdlib/include/qlc.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([lookup/2, find_by_name/3, find_all/1, insert/2, delete/2, size/1]).


%% Retrieve a record by key from the table.
%%
-spec(lookup({mnesia|ets, atom()}, integer()) ->
             tuple() | list() | {error, any()}).
lookup({mnesia, Table}, AccessKey) ->
    Fun = fun() ->
                  Q1 = qlc:q([X || X <- mnesia:table(Table),
                                   X#bucket.access_key =:= AccessKey]),
                  Q2 = qlc:sort(Q1, [{order, ascending}]),
                  qlc:e(Q2)
          end,
    leo_mnesia:read(Fun);

lookup({ets, Table}, AccessKey0) ->
    Ret = ets:foldl(fun({_,#bucket{access_key = AccessKey1} = Bucket}, Acc) when AccessKey0 == AccessKey1 ->
                            [Bucket|Acc];
                       (_, Acc) ->
                            Acc
                    end, [], Table),
    case Ret of
        [] ->
            not_found;
        _ ->
            {ok, lists:sort(Ret)}
    end.


%% @doc Retrieve a record by name
%%
-spec(find_by_name({mnesia|ets, atom()}, string(), string()) ->
             {ok, list()} | {error, any()}).
find_by_name({mnesia, Table}, AccessKey0, Name) ->
    Fun = fun() ->
                  Q1 = qlc:q([X || X <- mnesia:table(Table),
                                   X#bucket.name =:= Name]),
                  Q2 = qlc:sort(Q1, [{order, ascending}]),
                  qlc:e(Q2)
          end,
    case leo_mnesia:read(Fun) of
        {ok, [#bucket{access_key = AccessKey1} = H|_]} when AccessKey0 == AccessKey1 ->
            {ok, H};
        {ok, _} ->
            {error, forbidden};
        Other ->
            Other
    end;

find_by_name({ets, Table}, AccessKey0, Name0) ->
    case catch ets:lookup(Table, Name0) of
        {'EXIT', Cause} ->
            {error, Cause};
        [] ->
            not_found;
        [{_, #bucket{access_key = AccessKey1} = Value}|_] when AccessKey0 == AccessKey1 ->
            {ok, Value};
        _ ->
            {error, forbidden}
    end.


%% @doc Retrieve all buckets.
%%
-spec(find_all({mnesia|ets, atom()}) ->
             {ok, list()} | {error, any()}).
find_all({mnesia, Table}) ->
    Fun = fun() ->
                  Q1 = qlc:q([X || X <- mnesia:table(Table)]),
                  Q2 = qlc:sort(Q1, [{order, ascending}]),
                  qlc:e(Q2)
          end,
    leo_mnesia:read(Fun);
find_all(_) ->
    {error, badarg}.


%% @doc Insert a record into the table.
%%
-spec(insert({mnesia|ets, atom()}, #bucket{}) ->
             ok | {error, any()}).
insert({mnesia, Table}, Bucket) ->
    Fun = fun() -> mnesia:write(Table, Bucket, write) end,
    leo_mnesia:write(Fun);

insert({ets, Table}, #bucket{name = Name} = Value) ->
    case catch ets:insert(Table, {Name, Value}) of
        true ->
            ok;
        {'EXIT', Cause} ->
            {error, Cause}
    end.


%% @doc Remove a record from the table.
%%
-spec(delete({mnesia|ets, atom()}, #bucket{}) ->
             ok | {error, any()}).
delete({mnesia, Table}, #bucket{name       = Name,
                                access_key = AccessKey}) ->
    Fun1 = fun() ->
                   Q = qlc:q(
                         [X || X <- mnesia:table(leo_s3_buckets),
                               X#bucket.name =:= Name andalso X#bucket.access_key =:= AccessKey]),
                   qlc:e(Q)
           end,
    case leo_mnesia:read(Fun1) of
        {ok, [Value|_]} ->
            Fun2 = fun() ->
                           mnesia:delete_object(Table, Value, write)
                   end,
            leo_mnesia:delete(Fun2);
        Error ->
            Error
    end;

delete({ets, Table}, #bucket{name       = Name,
                             access_key = _AccessKey}) ->
    case ets:lookup(Table, Name) of
        [Value|_] ->
            case catch ets:delete_object(Table, Value) of
                true ->
                    ok;
                {'EXIT', Cause} ->
                    {error, Cause}
            end;
        [] ->
            ok;
        Error ->
            Error
    end.


%% @doc Retrieve total of records.
%%
-spec(size({mnesia|ets, atom()}) ->
             integer()).
size({mnesia, Table}) ->
    mnesia:ets(fun ets:info/2, [Table, size]);
size({ets, Table}) ->
    ets:info(Table, size).

