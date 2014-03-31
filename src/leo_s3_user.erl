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

-export([create_table/2,
         put/1, put/3, bulk_put/1,
         update/1, delete/1,
         find_by_id/1, find_all/0,
         auth/2, checksum/0,
         transform/0, transform/1
        ]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
%% @doc Create user table(mnesia)
%%
-spec(create_table(ram_copies|disc_copies, list()) ->
             ok).
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
             {del,        boolean, false}
            ]}
          ]),
    ok.


%% @doc Insert a user
%%
-spec(put(#?S3_USER{})  ->
             ok | {error, any()}).
put(#?S3_USER{} = User) ->
    leo_s3_libs_data_handler:insert({mnesia, ?USERS_TABLE},
                                    {[], User}).


%% @doc Create a user account
%%
-spec(put(binary(), binary(), boolean()) ->
             {ok, list(tuple())} | {error, any()}).
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
                    {ok, []}
            end;
        Error ->
            Error
    end.


%% @doc Add buckets
%%
-spec(bulk_put(list(#?S3_USER{})) ->
             ok).
bulk_put([]) ->
    ok;
bulk_put([User|Rest]) ->
    _ = ?MODULE:put(User),
    bulk_put(Rest).


%% @doc Update a user
%%
-spec(update(#?S3_USER{}) ->
             ok | {error, any()}).
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
            Password2 = case (Password0 == <<>> orelse
                              Password0 == []) of
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
        Error ->
            Error
    end.


%% @doc Delete a user
%%
-spec(delete(integer()) ->
             ok | {error, any()}).
delete(UserId) ->
    case find_by_id(UserId) of
        {ok, #?S3_USER{role_id    = RoleId,
                       password   = Password,
                       created_at = CreatedAt}} ->
            case leo_s3_libs_data_handler:insert({mnesia, ?USERS_TABLE},
                                                 {[], #?S3_USER{id         = UserId,
                                                                role_id    = RoleId,
                                                                password   = Password,
                                                                created_at = CreatedAt,
                                                                updated_at = leo_date:now(),
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
             {ok, #?S3_USER{}} | not_found | {error, any()}).
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
             {ok, list(#?S3_USER{})} | not_found | {error, any()}).
find_all() ->
    case leo_s3_bucket_data_handler:find_all({mnesia, ?USERS_TABLE}) of
        {ok, RetL} ->
            {ok, RetL};
        Error ->
            Error
    end.


%% @doc Retrieve owners (omit secret_key)
%%
-spec(auth(binary(), binary()) ->
             {ok, #?S3_USER{}} | {error, invalid_values}).
auth(UserId, PW0) ->
    case find_by_id(UserId) of
        {ok, #?S3_USER{password = PW1,
                       created_at = CreatedAt} = User} ->
            case hash_and_salt_password(PW0, CreatedAt) of
                PW1 ->
                    {ok, User#?S3_USER{password = []}};
                _ ->
                    %% migrate previous-version(v0.12.7)'s data
                    case erlang:md5(PW0) of
                        PW1 ->
                            _ = update(User),
                            {ok, User#?S3_USER{password = []}};
                        _ ->
                            {error, invalid_values}
                    end
            end;
        _Other ->
            {error, invalid_values}
    end.


%% @doc Retrieve checksum of the table
%%
-spec(checksum() ->
             {ok, pos_integer()} | not_found | {error, any()}).
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
    ok.

%% @doc the record is the current verion
%% @private
transform_1(#?S3_USER{} = User) ->
    User;
transform_1(#user{id = Id,
                  password = Password,
                  role_id  = RoleId,
                  created_at = CreatedAt,
                  del = DelFlag}) ->
    #?S3_USER{id = Id,
              password = Password,
              role_id  = RoleId,
              created_at = CreatedAt,
              updated_at = CreatedAt,
              del = DelFlag}.


%% @doc Transform (set cluster-id to every records)
-spec(transform(atom()) ->
             ok).
transform(ClusterId) ->
    Fun = fun() ->
                  Q1 = qlc:q([X || X <- mnesia:table(?USERS_TABLE)]),
                  Q2 = qlc:sort(Q1, [{order, ascending}]),
                  qlc:e(Q2)
          end,
    case leo_mnesia:read(Fun) of
        {ok, RetL} ->
            transform_2(RetL, ClusterId);
        _ ->
            ok
    end.

transform_2([],_ClusterId) ->
    ok;
transform_2([#?S3_USER{cluster_id = undefined} = User|Rest], ClusterId) ->
    leo_s3_libs_data_handler:insert(
      {mnesia, ?USERS_TABLE},
      {[], User#?S3_USER{cluster_id = ClusterId}}),
    transform_2(Rest, ClusterId);
transform_2([_|Rest], ClusterId) ->
    transform_2(Rest, ClusterId).


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

