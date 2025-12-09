%%======================================================================
%%
%% Leo S3-Libs
%%
%% Copyright (c) 2012-2018 Rakuten, Inc.
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
    {setup,
     fun setup/0,
     fun teardown/1,
     [
      {timeout, 60, fun suite_/0}
     ]}.

setup() ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(bcrypt),
    application:ensure_all_started(mnesia),
    leo_s3_auth:start(master, []),
    ok.

teardown(_) ->
    application:stop(mnesia),
    application:stop(bcrypt),
    application:stop(poolboy),
    application:stop(crypto),
    meck:unload(),
    ok.


suite_() ->
    ok = leo_s3_user:create_table(ram_copies, [node()]),
    ok = leo_s3_user_credential:create_table(ram_copies, [node()]),
    catch leo_s3_auth:create_table(ram_copies, [node()]),

    %% create a user
    UserId_1 = <<"Leo">>,
    Password_1 = <<"FastStorage">>,
    {ok, Keys_1} = leo_s3_user:create(UserId_1, Password_1),
    AccessKeyId_1 = leo_misc:get_value('access_key_id', Keys_1),
    SecretAccessKey_1 = leo_misc:get_value('secret_access_key', Keys_1),

    ?assertEqual(2, length(Keys_1)),
    ?assertEqual(true, AccessKeyId_1 /= <<>>),
    ?assertEqual(true, SecretAccessKey_1 /= <<>>),

    {ok, #?S3_USER{id = UserId_1,
                   password = PWHash_1,
                   role_id = ?ROLE_GENERAL,
                   del = false}} = leo_s3_user:find_by_id(UserId_1),
    ?assertEqual(true, erlpass:match(Password_1, PWHash_1)),


    %% create-user
    UserId_2 = <<"Name is Leo">>,
    Password_2 = <<"Type is FS">>,

    {ok, Keys_2} = leo_s3_user:create(UserId_2, Password_2),
    AccessKeyId = leo_misc:get_value('access_key_id', Keys_2),
    SecretAccessKey = leo_misc:get_value('secret_access_key', Keys_2),

    ?assertEqual(2, length(Keys_2)),
    ?assertEqual(true, AccessKeyId /= <<>>),
    ?assertEqual(true, SecretAccessKey /= <<>>),

    {error,already_exists} =
        leo_s3_user:create(UserId_2, Password_2),

    %% migration from 0.12.7 to 1.3.3
    {ok, _} = leo_s3_user:create(<< UserId_2/binary, "_md5" >>, Password_2, 'md5'),
    {ok, ResMD5} = leo_s3_user:find_by_id(<< UserId_2/binary, "_md5" >>),
    ?debugVal(ResMD5),
    {ok, _} = leo_s3_user:auth(<< UserId_2/binary, "_md5" >>, Password_2),
    {ok, ResBcrypted} = leo_s3_user:find_by_id(<< UserId_2/binary, "_md5" >>),
    ?debugVal(ResBcrypted),

    %% migration from 1.3.2 to 1.3.3
    {ok, _} = leo_s3_user:create(<< UserId_2/binary, "_md5_w/salt" >>, Password_2, 'md5_with_salt'),
    {ok, ResMD5WithSalt} = leo_s3_user:find_by_id(<< UserId_2/binary, "_md5_w/salt" >>),
    ?debugVal(ResMD5WithSalt),
    {ok, _} = leo_s3_user:auth(<< UserId_2/binary, "_md5_w/salt" >>, Password_2),
    {ok, ResBcrypted2} = leo_s3_user:find_by_id(<< UserId_2/binary, "_md5_w/salt" >>),
    ?debugVal(ResBcrypted2),

    %% %% import-user
    ImportUserId = <<"Name is Import">>,
    ImportAccessKey = <<"importA">>,
    ImportSecretKey = <<"importS">>,
    {ok, IKeys} = leo_s3_user:import(ImportUserId, ImportAccessKey, ImportSecretKey),
    IAccessKeyId = leo_misc:get_value('access_key_id', IKeys),
    ISecretAccessKey = leo_misc:get_value('secret_access_key', IKeys),
    ?assertEqual(2, length(IKeys)),
    ?assertEqual(IAccessKeyId, ImportAccessKey),
    ?assertEqual(ISecretAccessKey, ImportSecretKey),

    %% %% find-by-id
    {ok, Res1} = leo_s3_user:find_by_id(UserId_2),
    ?assertEqual(UserId_2, Res1#?S3_USER.id),
    ?debugVal(Res1#?S3_USER.password),

    %% %% find_by_access_key_id
    {ok, Res2} = leo_s3_user_credential:find_by_access_key_id(AccessKeyId),
    ?assertEqual(UserId_2, Res2#user_credential.user_id),
    ?assertEqual(AccessKeyId, Res2#user_credential.access_key_id),

    %% %% find_all
    %% @OTODO
    {ok, _} = leo_s3_user:create(<< UserId_2/binary, "_1" >>, Password_2),
    {ok, _} = leo_s3_user:create(<< UserId_2/binary, "_2" >>, Password_2),
    {ok, _} = leo_s3_user:create(<< UserId_2/binary, "_3" >>, Password_2),
    {ok, _} = leo_s3_user:create(<< UserId_2/binary, "_4" >>, Password_2),
    {ok, Users_1} = leo_s3_user_credential:find_all(),
    {ok, Users_2} = leo_s3_user_credential:find_all_with_role(),
    ?debugVal(Users_1),
    ?debugVal(Users_2),
    ?assertEqual(9, length(Users_1)),
    ?assertEqual(9, length(Users_2)),

    %% get_credential_by_id
    {ok, Credential} = leo_s3_user_credential:get_credential_by_user_id(UserId_2),
    ?assertEqual(AccessKeyId, leo_misc:get_value(access_key_id, Credential)),
    ?assertEqual(SecretAccessKey, leo_misc:get_value(secret_access_key, Credential)),

    %% auth,
    {ok, _} = leo_s3_user:auth(UserId_2, Password_2),
    {error,invalid_values} = leo_s3_user:auth(UserId_2, <<>>),

    %% update
    ok = leo_s3_user:update(#?S3_USER{id = UserId_2,
                                      role_id = 9}),
    {ok, Res3} = leo_s3_user:find_by_id(UserId_2),
    ?assertEqual(UserId_2, Res3#?S3_USER.id),
    ?assertEqual(9, Res3#?S3_USER.role_id),

    %% delete
    {ok, ALL_1} = leo_s3_user_credential:find_all_with_role(),
    ok = leo_s3_user:delete(UserId_2),
    not_found = leo_s3_user:find_by_id(UserId_2),
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

    %% delete_all_related_records
    UID4Delete = <<UserId_2/binary, "_1">>,

    %% retreive access_key_id
    {ok, Creds4Delete} = leo_s3_user_credential:get_credential_by_user_id(UID4Delete),
    ok = leo_s3_user:delete_all_related_records(UID4Delete),
    not_found = leo_s3_user:find_by_id(UID4Delete),
    not_found = leo_s3_user_credential:get_credential_by_user_id(UID4Delete),
    not_found = leo_s3_auth:get_credential(leo_misc:get_value(access_key_id, Creds4Delete)),

    %% force import-user
    ImportUserId2 = <<"Name is Import2">>,
    %% just in case, import doesn't work for a different user with the existing access_key_id
    {error, already_exists} = leo_s3_user:import(ImportUserId2, ImportAccessKey, ImportSecretKey),

    ImportSecretKey2 = <<"importS2">>,
    {ok, IKeys2} = leo_s3_user:force_import(ImportUserId2, ImportAccessKey, ImportSecretKey2),
    IAccessKeyId2 = leo_misc:get_value('access_key_id', IKeys2),
    ISecretAccessKey2 = leo_misc:get_value('secret_access_key', IKeys2),
    ?assertEqual(2, length(IKeys)),
    ?assertEqual(IAccessKeyId2, ImportAccessKey),
    ?assertEqual(ISecretAccessKey2, ImportSecretKey2),
    ok.

-endif.
