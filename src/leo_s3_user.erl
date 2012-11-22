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
%% Leo S3 Libs - User
%% @doc
%% @end
%%======================================================================
-module(leo_s3_user).

-author('Yosuke Hara').

-include("leo_s3_auth.hrl").
-include("leo_s3_user.hrl").
-include("leo_s3_libs.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([create_user_table/2, create_user_credential_table/2,
         create_user/3, find_by_id/1, find_by_access_key_id/1, find_users_all/0,
         get_credential_by_id/1, auth/2
        ]).

-define(USERS_TABLE,           leo_s3_users).
-define(USER_CREDENTIAL_TABLE, leo_s3_user_credential).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
%% @doc Create user table(mnesia)
%%
-spec(create_user_table(ram_copies|disc_copies, list()) ->
             ok).
create_user_table(Mode, Nodes) ->
    {atomic, ok} =
        mnesia:create_table(
          ?USERS_TABLE,
          [{Mode, Nodes},
           {type, set},
           {record_name, user},
           {attributes, record_info(fields, user)},
           {user_properties,
            [{id,         {binary,  undefined}, false, primary,   undefined, identity,  binary },
             {password,   {binary,  undefined}, false, undefined, undefined, undefined, binary },
             {role_id,    {integer, undefined}, false, undefined, undefined, undefined, integer},
             {created_at, {integer, undefined}, false, undefined, undefined, undefined, integer}
            ]}
          ]),
    ok.


%% @doc Create user-credential table(mnesia)
%%
-spec(create_user_credential_table(ram_copies|disc_copies, list()) ->
             ok).
create_user_credential_table(Mode, Nodes) ->
    {atomic, ok} =
        mnesia:create_table(
          ?USER_CREDENTIAL_TABLE,
          [{Mode, Nodes},
           {type, set},
           {record_name, user_credential},
           {attributes, record_info(fields, user_credential)},
           {user_properties,
            [
             {user_id,       {binary, undefined}, false, primary,   undefined, identity,  binary},
             {access_key_id, {binary, undefined}, false, undefined, undefined, undefined, binary}
            ]}
          ]),
    ok.


%% @doc Create a user account
%%
-spec(create_user(binary(), binary(), boolean()) ->
             {ok, list(tuple())} | {error, any()}).
create_user(UserId, Password, WithS3Keys) ->
    case find_by_id(UserId) of
        not_found ->
            create_user1(UserId, Password, WithS3Keys);
        {ok, _} ->
            {error, already_exists};
        {error, Cause} ->
            {error, Cause}
    end.


%% @doc Create a user account w/access-key-id/secret-access-key
%% @private
create_user1(UserId, Password, WithS3Keys) ->
    CreatedAt = leo_date:now(),

    case leo_s3_libs_data_handler:insert(
           {mnesia, ?USERS_TABLE}, {[], #user{id         = UserId,
                                              password   = erlang:md5(Password),
                                              created_at = CreatedAt}}) of
        ok ->
            case WithS3Keys of
                true ->
                    create_user2(UserId, CreatedAt);
                false ->
                    {ok, []}
            end;
        Error ->
            Error
    end.

%% @doc Create a user account w/access-key-id/secret-access-key
%% @private
create_user2(UserId, CreatedAt) ->
    case leo_s3_auth:create_key(binary_to_list(UserId)) of
        {ok, Keys} ->
            AccessKeyId = leo_misc:get_value(access_key_id, Keys),

            case leo_s3_libs_data_handler:insert(
                   {mnesia, ?USER_CREDENTIAL_TABLE},
                   {[], #user_credential{user_id       = UserId,
                                         access_key_id = AccessKeyId,
                                         created_at    = CreatedAt}}) of
                ok ->
                    {ok, Keys};
                Error ->
                    Error
            end;
        Error ->
            ?debugVal(Error),
            Error
    end.


%% @doc Retrieve a user by user-id
%%
-spec(find_by_id(binary()) ->
             {ok, #user{}} | not_found | {error, any()}).
find_by_id(UserId) ->
    F = fun() ->
                Q = qlc:q([X || X <- mnesia:table(?USERS_TABLE),
                                X#user.id =:= UserId]),
                qlc:e(Q)
        end,
    case leo_mnesia:read(F) of
        {ok, [User|_]} ->
            {ok, User};
        Other ->
            Other
    end.


%% @doc Retrieve a use by access-key-id
%%
-spec(find_by_access_key_id(binary()) ->
             {ok, #user_credential{}} | not_found | {error, any()}).
find_by_access_key_id(AccessKeyId) ->
    F = fun() ->
                Q = qlc:q([X || X <- mnesia:table(?USER_CREDENTIAL_TABLE),
                                X#user_credential.access_key_id =:= AccessKeyId]),
                qlc:e(Q)
        end,
    case leo_mnesia:read(F) of
        {ok, [UserCredential|_]} ->
            {ok, UserCredential};
        Other ->
            Other
    end.


%% @doc Retrieve owners (omit secret_key)
%%
-spec(find_users_all() ->
             {ok, list(#user_credential{})} | {error, any()}).
find_users_all() ->
    Fun = fun() ->
                  Q1 = qlc:q([X || X <- mnesia:table(?USER_CREDENTIAL_TABLE)]),
                  Q2 = qlc:sort(Q1, [{order, ascending}]),
                  qlc:e(Q2)
          end,
    case leo_mnesia:read(Fun) of
        {error, Cause} ->
            {error, Cause};
        not_found ->
            not_found;
        {ok, Users} ->
            {ok, Users}
    end.


%% @doc Retrieve credential by user-id
%%
-spec(get_credential_by_id(binary()) ->
             {ok, list(tuple())} | not_found | {error, any()}).
get_credential_by_id(UserId) ->
    F = fun() ->
                Q = qlc:q([X || X <- mnesia:table(?USER_CREDENTIAL_TABLE),
                                X#user_credential.user_id =:= UserId]),
                qlc:e(Q)
        end,
    case leo_mnesia:read(F) of
        {ok, [#user_credential{user_id       = UserId,
                               access_key_id = AccessKeyId,
                               created_at    = CreatedAt}|_]} ->
            case leo_s3_auth:get_credential(AccessKeyId) of
                {ok, [#credential{secret_access_key = SecretAccessKey}|_]} ->
                    {ok, [{user_id,           UserId},
                          {access_key_id,     AccessKeyId},
                          {secret_access_key, SecretAccessKey},
                          {created_at,        CreatedAt}]};
                Other ->
                    Other
            end;
        Other ->
            Other
    end.



%% @doc Retrieve owners (omit secret_key)
%%
-spec(auth(binary(), binary()) ->
             {ok, #user{}} | {error, invalid_values}).
auth(UserId, PW0) ->
    PW1 = erlang:md5(PW0),

    case find_by_id(UserId) of
        {ok, #user{password = PW2} = User} when PW1 == PW2 ->
            {ok, User#user{password = []}};
        _Other ->
            {error, invalid_values}
    end.


%%--------------------------------------------------------------------
%%% INTERNAL FUNCTIONS
%%--------------------------------------------------------------------

