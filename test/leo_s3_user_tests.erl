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
%% Leo S3-Libs - User TEST
%% @doc
%% @end
%%======================================================================
-module(leo_s3_user_tests).

-author('Yosuke Hara').

-include("leo_s3_auth.hrl").
-include("leo_s3_user.hrl").
-include("leo_s3_libs.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/qlc.hrl").


%%--------------------------------------------------------------------
%% TEST
%%--------------------------------------------------------------------
-ifdef(EUNIT).

bucket_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [{with, [T]} || T <- [fun suite_/1
                          ]]}.

setup() ->
    application:start(crypto),
    application:start(mnesia),
    leo_s3_auth:start(master, []),
    ok.

teardown(_) ->
    application:stop(crypto),
    application:stop(mnesia),
    meck:unload(),
    ok.


suite_(_) ->
    ok = leo_s3_user:create_table(ram_copies, [node()]),
    ok = leo_s3_user_credential:create_table(ram_copies, [node()]),
    ok = leo_s3_auth:create_table(ram_copies, [node()]),

    UserId    = <<"Name is Leo">>,
    Password0 = <<"Type is FS">>,

    %% %% create-user
    {ok, Keys} = leo_s3_user:put(UserId, Password0, true),
    AccessKeyId     = leo_misc:get_value('access_key_id',     Keys),
    SecretAccessKey = leo_misc:get_value('secret_access_key', Keys),

    ?assertEqual(2, length(Keys)),
    ?assertEqual(true, AccessKeyId     /= <<>>),
    ?assertEqual(true, SecretAccessKey /= <<>>),

    {error,already_exists} =
        leo_s3_user:put(UserId, Password0, true),

    %% %% find-by-id
    {ok, Res1} = leo_s3_user:find_by_id(UserId),
    ?assertEqual(UserId, Res1#?S3_USER.id),
    ?debugVal(Res1#?S3_USER.password),

    %% %% find_by_access_key_id
    {ok, Res2} = leo_s3_user_credential:find_by_access_key_id(AccessKeyId),
    ?assertEqual(UserId,      Res2#user_credential.user_id),
    ?assertEqual(AccessKeyId, Res2#user_credential.access_key_id),

    %% %% find_all
    {ok, _} = leo_s3_user:put(<< UserId/binary, "_1" >>, Password0, true),
    {ok, _} = leo_s3_user:put(<< UserId/binary, "_2" >>, Password0, true),
    {ok, _} = leo_s3_user:put(<< UserId/binary, "_3" >>, Password0, true),
    {ok, _} = leo_s3_user:put(<< UserId/binary, "_4" >>, Password0, true),
    {ok, Users_1} = leo_s3_user_credential:find_all(),
    {ok, Users_2} = leo_s3_user_credential:find_all_with_role(),
    ?debugVal(Users_1),
    ?debugVal(Users_2),
    ?assertEqual(5, length(Users_1)),
    ?assertEqual(5, length(Users_2)),

    %% %% get_credential_by_id
    {ok, Credential} = leo_s3_user_credential:get_credential_by_user_id(UserId),
    ?assertEqual(AccessKeyId,     leo_misc:get_value(access_key_id, Credential)),
    ?assertEqual(SecretAccessKey, leo_misc:get_value(secret_access_key, Credential)),

    %% auth,
    {ok, _} = leo_s3_user:auth(UserId, Password0),
    {error,invalid_values} = leo_s3_user:auth(UserId, <<>>),

    %% update
    ok = leo_s3_user:update(#?S3_USER{id      = UserId,
                                      role_id = 9}),
    {ok, Res3} = leo_s3_user:find_by_id(UserId),
    ?assertEqual(UserId, Res3#?S3_USER.id),
    ?assertEqual(9,      Res3#?S3_USER.role_id),

    %% delete
    {ok, ALL_1} = leo_s3_user_credential:find_all_with_role(),
    ok = leo_s3_user:delete(UserId),
    not_found = leo_s3_user:find_by_id(UserId),
    {ok, ALL_2} = leo_s3_user_credential:find_all_with_role(),
    ?assertEqual(1, length(ALL_1) - length(ALL_2)),

    %% check checksum
    {ok, Checksum_1} = leo_s3_user:checksum(),
    {ok, Checksum_2} = leo_s3_user_credential:checksum(),
    ?assertEqual(true, Checksum_1 > 0),
    ?assertEqual(true, Checksum_2 > 0),


    %% check bulk-insert
    {ok, RetL_1} = leo_s3_user:find_all(),
    ok = leo_s3_user:bulk_put([#?S3_USER{id = 1},
                               #?S3_USER{id = 2},
                               #?S3_USER{id = 3},
                               #?S3_USER{id = 4},
                               #?S3_USER{id = 5}]),
    {ok, RetL_2} = leo_s3_user:find_all(),
    ?assertEqual(5, length(RetL_2) - length(RetL_1)),

    {ok, RetL_3} = leo_s3_user_credential:find_all(),
    ok = leo_s3_user_credential:bulk_put([#user_credential{user_id = 1},
                                          #user_credential{user_id = 2},
                                          #user_credential{user_id = 3},
                                          #user_credential{user_id = 4},
                                          #user_credential{user_id = 5}]),
    {ok, RetL_4} = leo_s3_user_credential:find_all(),
    ?assertEqual(5, length(RetL_4) - length(RetL_3)),

    ok.

-endif.

