%%======================================================================
%%
%% Leo S3-Libs
%%
%% Copyright (c) 2012-2013 Rakuten, Inc.
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
         add/3, update/1, delete/1,
         find_by_id/1, find_by_access_key_id/1, find_all/0,
         get_credential_by_id/1, auth/2
        ]).

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
             {created_at, {integer, undefined}, false, undefined, undefined, undefined, integer},
             {del,        {boolean, undefined}, false, undefined, undefined, undefined, boolean}
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
-spec(add(binary(), binary(), boolean()) ->
             {ok, list(tuple())} | {error, any()}).
add(UserId, Password, WithS3Keys) ->
    case find_by_id(UserId) of
        not_found ->
            add1(UserId, Password, WithS3Keys);
        {ok, _} ->
            {error, already_exists};
        {error, Cause} ->
            {error, Cause}
    end.


%% @doc Create a user account w/access-key-id/secret-access-key
%% @private
add1(UserId, Password, WithS3Keys) ->
    CreatedAt = leo_date:now(),
    Digest = hash_and_salt_password(Password, CreatedAt),

    case leo_s3_libs_data_handler:insert(
           {mnesia, ?USERS_TABLE}, {[], #user{id         = UserId,
                                              password   = Digest,
                                              created_at = CreatedAt}}) of
        ok ->
            case WithS3Keys of
                true ->
                    add2(UserId, CreatedAt);
                false ->
                    {ok, []}
            end;
        Error ->
            Error
    end.

%% @doc Create a user account w/access-key-id/secret-access-key
%% @private
add2(UserId0, CreatedAt) ->
    UserId1 = case is_binary(UserId0) of
                  true  -> binary_to_list(UserId0);
                  false -> UserId0
              end,

    case leo_s3_auth:create_key(UserId1) of
        {ok, Keys} ->
            AccessKeyId = leo_misc:get_value(access_key_id, Keys),

            case leo_s3_libs_data_handler:insert(
                   {mnesia, ?USER_CREDENTIAL_TABLE},
                   {[], #user_credential{user_id       = UserId1,
                                         access_key_id = AccessKeyId,
                                         created_at    = CreatedAt}}) of
                ok ->
                    {ok, Keys};
                Error ->
                    Error
            end;
        Error ->
            Error
    end.


%% @doc Update a user
%%
-spec(update(#user{}) ->
             ok | {error, any()}).
update(#user{id       = UserId,
             role_id  = RoleId0,
             password = Password0}) ->
    case find_by_id(UserId) of
        {ok, #user{role_id    = RoleId1,
                   password   = Password1,
                   created_at = CreatedAt}} ->

            RoleId2 = case (RoleId0 == 0) of
                          true  -> RoleId1;
                          false -> RoleId0
                      end,
            Password2 = case (Password0 == <<>> orelse
                              Password0 == []) of
                            true  -> Password1;
                            false -> hash_and_salt_password(Password0, CreatedAt)
                        end,

            leo_s3_libs_data_handler:insert(
              {mnesia, ?USERS_TABLE}, {[], #user{id         = UserId,
                                                 role_id    = RoleId2,
                                                 password   = Password2,
                                                 created_at = CreatedAt}});
        Error ->
            Error
    end.


%% @doc Delete a user
%%
-spec(delete(integer()) ->
             ok | {error, any()}).
delete(UserId) ->
    case find_by_id(UserId) of
        {ok, #user{role_id    = RoleId,
                   password   = Password,
                   created_at = CreatedAt}} ->
            case leo_s3_libs_data_handler:insert(
                   {mnesia, ?USERS_TABLE}, {[], #user{id         = UserId,
                                                      role_id    = RoleId,
                                                      password   = Password,
                                                      created_at = CreatedAt,
                                                      del        = true}}) of
                ok ->
                    leo_s3_libs_data_handler:delete(
                      {mnesia, ?USER_CREDENTIAL_TABLE}, UserId);
                Error ->
                    Error
            end;
        Error ->
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
            case User#user.del of
                true ->
                    not_found;
                false ->
                    {ok, User}
            end;
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
-spec(find_all() ->
             {ok, list(#user_credential{})} | {error, any()}).
find_all() ->
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
        {ok, Users0} ->
            Users1 = lists:map(fun(#user_credential{user_id = UserId,
                                                    access_key_id = AccessKeyId,
                                                    created_at = CretedAt}) ->
                                       {ok, #user{role_id = RoleId}} = find_by_id(UserId),
                                       [{user_id, UserId}, {role_id, RoleId},
                                        {access_key_id, AccessKeyId}, {created_at, CretedAt}]
                               end, Users0),
            {ok, Users1}
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
                {ok, Credential} ->
                    {ok, [{user_id,           UserId},
                          {access_key_id,     AccessKeyId},
                          {secret_access_key, Credential#credential.secret_access_key},
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
    case find_by_id(UserId) of
        {ok, #user{password = PW1,
                   created_at = CreatedAt} = User} ->
            case hash_and_salt_password(PW0, CreatedAt) of
                PW1 ->
                    {ok, User#user{password = []}};
                _ ->
                    %% migrate previous-version(v0.12.7)'s data
                    case erlang:md5(PW0) of
                        PW1 ->
                            _ = update(User),
                            {ok, User#user{password = []}};
                        _ ->
                            {error, invalid_values}
                    end
            end;
        _Other ->
            {error, invalid_values}
    end.


%%--------------------------------------------------------------------
%%% INTERNAL FUNCTIONS
%%--------------------------------------------------------------------
%% @doc Generate hash/salt-ed password
%% @private
-spec(hash_and_salt_password(binary(), integer()) ->
             binary()).
hash_and_salt_password(Password, CreatedAt) ->
    Salt = list_to_binary(leo_hex:integer_to_hex(CreatedAt, 8)),
    Context1 = crypto:hash_init(md5),
    Context2 = crypto:hash_update(Context1, Password),
    Context3 = crypto:hash_update(Context2, Salt),
    crypto:hash_final(Context3).

