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
%% Leo S3 Libs - Bucket - ETS/Mnesia Data Handler
%% @doc The bucket record handler
%% @reference https://github.com/leo-project/leo_s3_libs/blob/master/src/leo_s3_bucket_data_handler.erl
%% @end
%%======================================================================
-module(leo_s3_bucket_data_handler).

-author('Yosuke Hara').

-include("leo_s3_bucket.hrl").
-include_lib("stdlib/include/qlc.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([lookup/2, find_by_name/2, find_by_name/3, find_by_name/4,
         find_all/1, insert/2, delete/2, size/1]).


%% Retrieve a record by key from the table.
%%
-spec(lookup({DB, Table}, AccessKey) ->
             {ok, [#?BUCKET{}]} | not_found | {error, any()} when DB::mnesia|ets,
                                                                  Table::atom(),
                                                                  AccessKey::binary()).
lookup({mnesia, Table}, AccessKey) ->
    Fun = fun() ->
                  Q1 = qlc:q([X || X <- mnesia:table(Table),
                                   (X#?BUCKET.access_key_id =:= AccessKey andalso
                                    X#?BUCKET.del =:= false)]),
                  Q2 = qlc:sort(Q1, [{order, ascending}]),
                  qlc:e(Q2)
          end,
    leo_mnesia:read(Fun);

lookup({ets, Table}, AccessKey0) ->
    Ret = ets:foldl(fun({_,#?BUCKET{access_key_id = AccessKey1,
                                    del = Del} = Bucket}, Acc)
                          when AccessKey0 == AccessKey1 andalso
                               Del == false ->
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
-spec(find_by_name(DBInfo, Name) ->
             {ok, #?BUCKET{}} | not_found | {error, any()} when DBInfo::{mnesia|ets, atom()},
                                                                Name::binary()).
find_by_name(DBInfo, Name) ->
    find_by_name(DBInfo, <<>>, Name, false).

-spec(find_by_name(DBInfo, AccessKey, Name) ->
             {ok, #?BUCKET{}} | not_found | {error, any()} when DBInfo::{mnesia|ets, atom()},
                                                                AccessKey::binary(),
                                                                Name::binary()).
find_by_name(DBInfo, AccessKey, Name) ->
    find_by_name(DBInfo, AccessKey, Name, true).

-spec(find_by_name(DBInfo, AccessKey0, Name, NeedAccessKey) ->
             {ok, #?BUCKET{}} | not_found | {error, any()} when DBInfo::{mnesia|ets, atom()},
                                                                AccessKey0::binary(),
                                                                Name::binary(),
                                                                NeedAccessKey::boolean()).
find_by_name({mnesia, Table}, AccessKey0, Name, NeedAccessKey) ->
    Fun = fun() ->
                  Q1 = qlc:q([X || X <- mnesia:table(Table),
                                   (X#?BUCKET.name =:= Name andalso
                                    X#?BUCKET.del  =:= false)]),
                  Q2 = qlc:sort(Q1, [{order, ascending}]),
                  qlc:e(Q2)
          end,
    case leo_mnesia:read(Fun) of
        {ok, [#?BUCKET{access_key_id = AccessKey1} = H|_]} when NeedAccessKey == false orelse
                                                                AccessKey0 == AccessKey1 ->
            {ok, H};
        {ok, _} ->
            {error, forbidden};
        Other ->
            Other
    end;

find_by_name({ets, Table}, AccessKey0, Name0, NeedAccessKey) ->
    case catch ets:lookup(Table, Name0) of
        {'EXIT', Cause} ->
            {error, Cause};
        [] ->
            not_found;
        [{_, #?BUCKET{access_key_id = AccessKey1} = Value}|_] when NeedAccessKey == false orelse
                                                                   AccessKey0 == AccessKey1 ->
            {ok, Value};
        _ ->
            {error, forbidden}
    end.


%% @doc Retrieve all buckets.
%%
-spec(find_all(DBInfo) ->
             {ok, [#?BUCKET{}]} | not_found | {error, any()} when DBInfo::{mnesia|ets, atom()}).
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
-spec(insert(DBInfo, Bucket) ->
             ok | {error, any()} when DBInfo::{mnesia|ets, atom()},
                                      Bucket::#?BUCKET{}).
insert({mnesia, Table}, Bucket) ->
    Fun = fun() -> mnesia:write(Table, Bucket, write) end,
    leo_mnesia:write(Fun);

insert({ets, Table}, #?BUCKET{name = Name} = Value) ->
    case catch ets:insert(Table, {Name, Value}) of
        true ->
            ok;
        {'EXIT', Cause} ->
            {error, Cause}
    end.


%% @doc Remove a record from the table.
%%
-spec(delete(DBInfo, Bucket) ->
             ok | {error, any()} when DBInfo::{mnesia|ets, atom()},
                                      Bucket::#?BUCKET{}).
delete({mnesia, Table}, #?BUCKET{name = Name,
                                 access_key_id = AccessKey}) ->
    Fun1 = fun() ->
                   Q = qlc:q(
                         [X || X <- mnesia:table(leo_s3_buckets),
                               (X#?BUCKET.name =:= Name andalso
                                X#?BUCKET.access_key_id =:= AccessKey)]),
                   qlc:e(Q)
           end,
    case leo_mnesia:read(Fun1) of
        {ok, [Value|_]} ->
            Fun2 = fun() ->
                           mnesia:delete_object(Table, Value, write)
                   end,
            leo_mnesia:delete(Fun2);
        not_found = Cause ->
            {error, Cause};
        Error ->
            Error
    end;

delete({ets, Table}, #?BUCKET{name = Name,
                              access_key_id = _AccessKey}) ->
    case ets:lookup(Table, Name) of
        [Value|_] ->
            case catch ets:delete_object(Table, Value) of
                true ->
                    ok;
                {'EXIT', Cause} ->
                    {error, Cause}
            end;
        [] ->
            ok
    end.


%% @doc Retrieve total of records.
%%
-spec(size(DBInfo) ->
             non_neg_integer() when DBInfo::{mnesia|ets, atom()}).
size({mnesia, Table}) ->
    mnesia:ets(fun ets:info/2, [Table, size]);
size({ets, Table}) ->
    ets:info(Table, size).

