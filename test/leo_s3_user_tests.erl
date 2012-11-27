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
%% Leo S3-Libs - User TEST
%% @doc
%% @end
%%======================================================================
-module(leo_s3_user_tests).

-author('Yosuke Hara').

-include("leo_s3_auth.hrl").
-include("leo_s3_user.hrl").
-include_lib("eunit/include/eunit.hrl").


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
    ok = leo_s3_user:create_user_table(ram_copies, [node()]),
    ok = leo_s3_user:create_user_credential_table(ram_copies, [node()]),
    ok = leo_s3_auth:create_credential_table(ram_copies, [node()]),

    UserId    = "Name is Leo",
    Password0 = <<"Type is FS">>,
    Password1 = erlang:md5(Password0),

    %% %% create-user
    {ok, Keys} = leo_s3_user:add(UserId, Password0, true),
    AccessKeyId     = leo_misc:get_value('access_key_id',     Keys),
    SecretAccessKey = leo_misc:get_value('secret_access_key', Keys),

    ?assertEqual(2, length(Keys)),
    ?assertEqual(true, AccessKeyId     /= <<>>),
    ?assertEqual(true, SecretAccessKey /= <<>>),

    {error,already_exists} =
        leo_s3_user:add(UserId, Password0, true),

    %% %% find-by-id
    {ok, Res1} = leo_s3_user:find_by_id(UserId),
    ?assertEqual(UserId,    Res1#user.id),
    ?assertEqual(Password1, Res1#user.password),

    %% %% find_by_access_key_id
    {ok, Res2} = leo_s3_user:find_by_access_key_id(AccessKeyId),
    ?assertEqual(UserId,      Res2#user_credential.user_id),
    ?assertEqual(AccessKeyId, Res2#user_credential.access_key_id),

    %% %% find_users_all
    {ok, _} = leo_s3_user:add(UserId ++ "_1", Password0, true),
    {ok, _} = leo_s3_user:add(UserId ++ "_2", Password0, true),
    {ok, _} = leo_s3_user:add(UserId ++ "_3", Password0, true),
    {ok, _} = leo_s3_user:add(UserId ++ "_4", Password0, true),
    {ok, Users} = leo_s3_user:find_users_all(),
    ?assertEqual(5, length(Users)),

    %% %% get_credential_by_id
    {ok, Credential} = leo_s3_user:get_credential_by_id(UserId),
    ?assertEqual(AccessKeyId,     leo_misc:get_value(access_key_id, Credential)),
    ?assertEqual(SecretAccessKey, leo_misc:get_value(secret_access_key, Credential)),

    %% auth,
    {ok, _} = leo_s3_user:auth(UserId, Password0),
    {error,invalid_values} = leo_s3_user:auth(UserId, <<>>),

    %% update
    ok = leo_s3_user:update(#user{id      = UserId,
                                  role_id = 9}),
    {ok, Res3} = leo_s3_user:find_by_id(UserId),
    ?assertEqual(UserId,    Res3#user.id),
    ?assertEqual(9,         Res3#user.role_id),
    ?assertEqual(Password1, Res3#user.password),

    %% delete
    ok = leo_s3_user:delete(UserId),
    not_found = leo_s3_user:find_by_id(UserId),
    ok.

-endif.

