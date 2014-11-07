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
%% Leo S3 Libs - User
%% @doc The s3-user operation
%% @reference https://github.com/leo-project/leo_s3_libs/blob/master/src/leo_s3_user.erl
%% @end
%%======================================================================
-module(leo_s3_user).

-author('Yosuke Hara').

-include("leo_s3_auth.hrl").
-include("leo_s3_user.hrl").
-include("leo_s3_libs.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([create_table/2,
         put/1, put/3, bulk_put/1,
         update/1, delete/1,
         find_by_id/1, find_all/0,
         auth/2, checksum/0,
         transform/0
        ]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
%% @doc Create user table(mnesia)
%%
-spec(create_table(Mode, Nodes) ->
             ok when Mode::ram_copies|disc_copies,
                     Nodes::[atom()]).
create_table(Mode, Nodes) ->
    {atomic, ok} =
        mnesia:create_table(
          ?USERS_TABLE,
          [{Mode, Nodes},
           {type, set},
           {record_name, ?S3_USER},
           {attributes, record_info(fields, ?S3_USER)},
           {user_properties,
            [{id,         binary,  primary},
             {password,   binary,  fasle},
             {role_id,    integer, false},
             {created_at, integer, false},
             {updated_at, integer, false},
             {del,        boolean, false}
            ]}
          ]),
    ok.


%% @doc Insert a user
%%
-spec(put(User)  ->
             ok | {error, any()} when User::#?S3_USER{}).
put(#?S3_USER{id = UserId,
              updated_at = UpdatedAt_1} = User) ->
    User_1 = User#?S3_USER{id = leo_misc:any_to_binary(UserId)},

    case find_by_id(UserId) of
        {ok, #?S3_USER{updated_at = UpdatedAt_2}} when UpdatedAt_1 > UpdatedAt_2 ->
            put_1(User_1);
        not_found ->
            put_1(User_1);
        _ ->
            ok
    end.

%% @private
put_1(User) ->
    leo_s3_libs_data_handler:insert({mnesia, ?USERS_TABLE},
                                    {[], User}).


%% @doc Create a user account
%%
-spec(put(UserId, Password, WithS3Keys) ->
             ok | {ok, [tuple()]} |{error, any()} when UserId::binary(),
                                                       Password::binary(),
                                                       WithS3Keys::boolean()).
put(UserId, Password, WithS3Keys) ->
    case find_by_id(UserId) of
        not_found ->
            put_1(UserId, Password, WithS3Keys);
        {ok, _} ->
            {error, already_exists};
        {error, Cause} ->
            {error, Cause}
    end.


%% @doc Create a user account w/access-key-id/secret-access-key
%% @private
put_1(UserId, Password, WithS3Keys) ->
    CreatedAt = leo_date:now(),
    Digest = hash_and_salt_password(Password, CreatedAt),

    case leo_s3_libs_data_handler:insert({mnesia, ?USERS_TABLE},
                                         {[], #?S3_USER{id         = UserId,
                                                        password   = Digest,
                                                        created_at = CreatedAt,
                                                        updated_at = CreatedAt}}) of
        ok ->
            case WithS3Keys of
                true ->
                    leo_s3_user_credential:put(UserId, CreatedAt);
                false ->
                    ok
                end;
        Error ->
            Error
    end.


%% @doc Add buckets
%%
-spec(bulk_put(UserList) ->
             ok when UserList::[#?S3_USER{}]).
bulk_put([]) ->
    ok;
bulk_put([User|Rest]) ->
    _ = ?MODULE:put(User),
    bulk_put(Rest).


%% @doc Update a user
%%
-spec(update(User) ->
             ok | {error, any()} when User::#?S3_USER{}).
update(#?S3_USER{id       = UserId,
                 role_id  = RoleId0,
                 password = Password0}) ->
    case find_by_id(UserId) of
        {ok, #?S3_USER{role_id    = RoleId1,
                       password   = Password1,
                       created_at = CreatedAt}} ->
            RoleId2 = case (RoleId0 == 0) of
                          true  -> RoleId1;
                          false -> RoleId0
                      end,
            Password2 = case (Password0 == <<>>) of
                            true  -> Password1;
                            false -> hash_and_salt_password(Password0, CreatedAt)
                        end,
            leo_s3_libs_data_handler:insert({mnesia, ?USERS_TABLE},
                                            {[], #?S3_USER{id         = UserId,
                                                           role_id    = RoleId2,
                                                           password   = Password2,
                                                           created_at = CreatedAt,
                                                           updated_at = leo_date:now()
                                                          }});
        not_found = Cause ->
            {error, Cause};
        Error ->
            Error
    end.


%% @doc Delete a user
%%
-spec(delete(UserId) ->
             ok | {error, any()} when UserId::binary()).
delete(UserId) ->
    case find_by_id(UserId) of
        {ok, #?S3_USER{} = S3User} ->
            case leo_s3_libs_data_handler:insert(
                   {mnesia, ?USERS_TABLE},
                   {[], S3User#?S3_USER{updated_at = leo_date:now(),
                                        del        = true}}) of
                ok ->
                    ok;
                Error ->
                    Error
            end;
        not_found = Cause ->
            {error, Cause};
        Error ->
            Error
    end.


%% @doc Retrieve a user by user-id
%%
-spec(find_by_id(UserId) ->
             {ok, #?S3_USER{}} | not_found | {error, any()} when UserId::binary()).
find_by_id(UserId) ->
    F = fun() ->
                Q = qlc:q([X || X <- mnesia:table(?USERS_TABLE),
                                X#?S3_USER.id =:= UserId]),
                qlc:e(Q)
        end,
    case leo_mnesia:read(F) of
        {ok, [User|_]} ->
            case User#?S3_USER.del of
                true ->
                    not_found;
                false ->
                    {ok, User}
            end;
        Other ->
            Other
    end.


%% @doc Retrieve all records
-spec(find_all() ->
             {ok, [#?S3_USER{}]} | not_found | {error, any()}).
find_all() ->
    case leo_s3_bucket_data_handler:find_all({mnesia, ?USERS_TABLE}) of
        {ok, RetL} ->
            {ok, RetL};
        Error ->
            Error
    end.


%% @doc Retrieve owners (omit secret_key)
%%
-spec(auth(UserId, Passwd) ->
             {ok, #?S3_USER{}} | {error, invalid_values} when UserId::binary(),
                                                              Passwd::binary()).
auth(UserId, PW0) ->
    case find_by_id(UserId) of
        {ok, #?S3_USER{password = PW1,
                       created_at = CreatedAt} = User} ->
            case hash_and_salt_password(PW0, CreatedAt) of
                PW1 ->
                    {ok, User#?S3_USER{password = <<>>}};
                _ ->
                    %% migrate previous-version(v0.12.7)'s data
                    case erlang:md5(PW0) of
                        PW1 ->
                            _ = update(User),
                            {ok, User#?S3_USER{password = <<>>}};
                        _ ->
                            {error, invalid_values}
                    end
            end;
        not_found = Cause ->
            {error, Cause};
        _Other ->
            {error, invalid_values}
    end.


%% @doc Retrieve checksum of the table
%%
-spec(checksum() ->
             {ok, non_neg_integer()} | not_found | {error, any()}).
checksum() ->
    case find_all() of
        {ok, RetL} ->
            {ok, erlang:crc32(term_to_binary(RetL))};
        _Error ->
            {ok, -1}
    end.


%% @doc Transform data
-spec(transform() ->
             ok).
transform() ->
    {atomic, ok} = mnesia:transform_table(
                     ?USERS_TABLE, fun transform_1/1,
                     record_info(fields, ?S3_USER), ?S3_USER),
    transform_2(),
    ok.

%% @doc the record is the current verion
%% @private
transform_1(#?S3_USER{id =_Id,
                      password = Password} = User) ->
    PwBin = leo_misc:any_to_binary(Password),
    User#?S3_USER{password = PwBin};
transform_1(#user{id = Id,
                  password = Password,
                  role_id  = RoleId,
                  created_at = CreatedAt,
                  del = DelFlag}) ->
    #?S3_USER{id = Id,
              password = leo_misc:any_to_binary(Password),
              role_id  = RoleId,
              created_at = CreatedAt,
              updated_at = CreatedAt,
              del = DelFlag}.

%% @private
transform_2() ->
    case find_all() of
        {ok, RetL} ->
            transform_3(RetL);
        _ ->
            ok
    end.

%% @private
transform_3([]) ->
    ok;
transform_3([#?S3_USER{id = Id}|Rest]) when is_binary(Id) ->
    transform_3(Rest);
transform_3([#?S3_USER{id = Id} = User|Rest]) ->
    case leo_s3_user_credential:get_credential_by_user_id(Id) of
        {ok, Values} ->
            IdBin = leo_misc:any_to_binary(Id),
            AccessKey = leo_misc:get_value('access_key_id', Values, <<>>),
            CreatedAt = leo_misc:get_value('created_at', Values, leo_date:now()),

            leo_s3_user_credential:put(
              #user_credential{user_id = IdBin,
                               access_key_id = AccessKey,
                               created_at = CreatedAt}),
            put_1(User#?S3_USER{id = IdBin}),

            case leo_s3_libs_data_handler:delete({mnesia, ?USERS_TABLE}, Id) of
                ok ->
                    case leo_s3_user_credential:delete(Id) of
                        ok ->
                            ok;
                        _ ->
                            void
                    end;
                _ ->
                    void
            end;
        _ ->
            void
    end,
    transform_3(Rest).


%%--------------------------------------------------------------------
%%% INTERNAL FUNCTIONS
%%--------------------------------------------------------------------
%% @doc Generate hash/salt-ed password
%% @private
-spec(hash_and_salt_password(Password, CreatedAt) ->
             binary() when Password::binary(),
                           CreatedAt::non_neg_integer()).
hash_and_salt_password(Password, CreatedAt) ->
    Salt = list_to_binary(leo_hex:integer_to_hex(CreatedAt, 8)),
    Context1 = crypto:hash_init(md5),
    Context2 = crypto:hash_update(Context1, Password),
    Context3 = crypto:hash_update(Context2, Salt),
    crypto:hash_final(Context3).
