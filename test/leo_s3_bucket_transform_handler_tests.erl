%%====================================================================
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
%% -------------------------------------------------------------------
%% Leo S3 Lib - Auth Test
%% @doc
%% @end
%%====================================================================
-module(leo_s3_bucket_transform_handler_tests).
-author('Yosuke Hara').

-include("leo_s3_libs.hrl").
-include("leo_s3_bucket.hrl").
-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% TEST
%%--------------------------------------------------------------------
-ifdef(EUNIT).

-define(ACCESS_KEY_0, <<"leofs">>).

-define(Bucket0, <<"bucket0">>).
-define(Bucket1, <<"bucket1">>).
-define(Bucket2, <<"bucket2">>).

auth_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [{with, [T]} || T <- [fun transform_1_/1,
                           fun transform_2_/1
                          ]]}.

setup() ->
    application:start(crypto),
    ok.

teardown(_) ->
    application:stop(crypto),
    application:stop(mnesia),
    meck:unload(),
    ok.

transform_1_(_) ->
    %% Prepare
    ok = leo_s3_bucket:create_bucket_table_old_for_test('ram_copies', [node()]),
    ok = leo_s3_bucket_data_handler:insert({mnesia, ?BUCKET_TABLE},
                                           #bucket{name       = ?Bucket0,
                                                   access_key = ?ACCESS_KEY_0}),
    ok = leo_s3_bucket_data_handler:insert({mnesia, ?BUCKET_TABLE},
                                           #bucket{name       = ?Bucket1,
                                                   access_key = ?ACCESS_KEY_0}),
    ok = leo_s3_bucket_data_handler:insert({mnesia, ?BUCKET_TABLE},
                                           #bucket{name       = ?Bucket2,
                                                   access_key = ?ACCESS_KEY_0}),

    %% Transform
    ok = leo_s3_bucket_transform_handler:transform(),
    {ok, Ret} = leo_s3_bucket_data_handler:lookup({mnesia, ?BUCKET_TABLE}, ?ACCESS_KEY_0),
    transform_1_1(Ret),
    ok.

%% @private
transform_1_1([]) ->
    ok;
transform_1_1([Bucket|Rest]) ->
    ?assertEqual(true, is_record(Bucket, ?BUCKET)),
    transform_1_1(Rest).


transform_2_(_) ->
    %% Prepare
    ok = leo_s3_bucket:create_bucket_table('ram_copies', [node()]),
    ok = leo_s3_bucket_data_handler:insert({mnesia, ?BUCKET_TABLE},
                                           #?BUCKET{name       = ?Bucket0,
                                                    access_key = ?ACCESS_KEY_0,
                                                    last_synchroized_at = leo_date:now(),
                                                    created_at = leo_date:now()
                                                   }),
    ok = leo_s3_bucket_data_handler:insert({mnesia, ?BUCKET_TABLE},
                                           #?BUCKET{name       = ?Bucket2,
                                                    access_key = ?ACCESS_KEY_0,
                                                    last_synchroized_at = leo_date:now(),
                                                    created_at = leo_date:now()
                                                   }),
    ok = leo_s3_bucket_data_handler:insert({mnesia, ?BUCKET_TABLE},
                                           #?BUCKET{name       = ?Bucket2,
                                                    access_key = ?ACCESS_KEY_0,
                                                    last_synchroized_at = leo_date:now(),
                                                    created_at = leo_date:now()
                                                   }),

    %% Transform
    ok = leo_s3_bucket_transform_handler:transform(),
    {ok, Ret} = leo_s3_bucket_data_handler:lookup({mnesia, ?BUCKET_TABLE}, ?ACCESS_KEY_0),
    transform_1_1(Ret),
    ok.

-endif.
