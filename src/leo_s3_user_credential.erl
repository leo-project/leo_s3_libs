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
%% @doc The s3-user's credential record handler
%% @reference https://github.com/leo-project/leo_s3_libs/blob/master/src/leo_s3_user_credential.erl
%% @end
%%======================================================================
-module(leo_s3_user_credential).

-author('Yosuke Hara').

-include("leo_s3_auth.hrl").
-include("leo_s3_user.hrl").
-include("leo_s3_libs.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/qlc.hrl").

-export([create_table/2, put/1, put/2, bulk_put/1,
         delete/1,
         find_by_access_key_id/1,
         find_all/0, find_all_with_role/0,
         get_credential_by_user_id/1,
         checksum/0
        ]).


%% @doc Create user-credential table(mnesia)
%%
-spec(create_table(Mode, Nodes) ->
             ok when Mode::ram_copies|disc_copies,
                     Nodes::list()).
create_table(Mode, Nodes) ->
    {atomic, ok} =
        mnesia:create_table(
          ?USER_CREDENTIAL_TABLE,
          [{Mode, Nodes},
           {type, set},
           {record_name, user_credential},
           {attributes, record_info(fields, user_credential)},
           {user_properties,
            [
             {user_id,       binary, primary},
             {access_key_id, binary, false}
            ]}
          ]),
    ok.


%% @doc Create a user account w/access-key-id/secret-access-key
%%
-spec(put(UserCredential) ->
             ok | {ok, [tuple()]} | {error, any()} when UserCredential::#user_credential{}|binary).
put(UserCredential) when is_record(UserCredential, user_credential) ->
    leo_s3_libs_data_handler:insert({mnesia, ?USER_CREDENTIAL_TABLE},
                                    {[], UserCredential});
put(UserId) ->
    ?MODULE:put(UserId, leo_date:now()).


%% @doc Create a user account w/access-key-id/secret-access-key
%%
-spec(put(UserId, CreatedAt) ->
             ok | {ok, [tuple()]} | {error, any()} when UserId::binary(),
                                                        CreatedAt::non_neg_integer()).
put(UserId, CreatedAt) ->
    UserId_1 = leo_misc:any_to_binary(UserId),

    case leo_s3_auth:create_key(UserId_1) of
        {ok, Keys} ->
            AccessKeyId = leo_misc:get_value(access_key_id, Keys),

            case leo_s3_libs_data_handler:insert(
                   {mnesia, ?USER_CREDENTIAL_TABLE},
                   {[], #user_credential{user_id       = UserId_1,
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


%% @doc Add buckets
%%
-spec(bulk_put(UserCredentialList) ->
             ok when UserCredentialList::list(#user_credential{})).
bulk_put([]) ->
    ok;
bulk_put([UserCredential|Rest]) ->
    _ = ?MODULE:put(UserCredential),
    bulk_put(Rest).


%% @doc Remote a credential-user info
-spec(delete(UserId) ->
             ok | {error, any()} when UserId::binary()).
delete(UserId) ->
    leo_s3_libs_data_handler:delete(
      {mnesia, ?USER_CREDENTIAL_TABLE}, UserId).



%% @doc Retrieve a use by access-key-id
%%
-spec(find_by_access_key_id(AccessKeyId) ->
             {ok, #user_credential{}} | not_found | {error, any()} when AccessKeyId::binary()).
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


%% @doc Retrieve all records
%%
-spec(find_all() ->
             {ok, list(#user_credential{})} |
             not_found | {error, any()}).
find_all() ->
    Fun = fun() ->
                  Q1 = qlc:q([X || X <- mnesia:table(?USER_CREDENTIAL_TABLE)]),
                  Q2 = qlc:sort(Q1, [{order, ascending}]),
                  qlc:e(Q2)
          end,
    leo_mnesia:read(Fun).


%% @doc Retrieve all records with role
%%
-spec(find_all_with_role() ->
             {ok, list(#user_credential{})} |
             not_found | {error, any()}).
find_all_with_role() ->
    case find_all() of
        {ok, RetL} ->
            RetL_1 = find_all_with_role_1(RetL, []),
            {ok, RetL_1};
        Error ->
            Error
    end.

%% @private
find_all_with_role_1([], Acc) ->
    lists:reverse(Acc);
find_all_with_role_1([#user_credential{user_id = UserId,
                                       access_key_id = AccessKeyId,
                                       created_at = CretedAt}|Rest], Acc) ->
    case leo_s3_user:find_by_id(UserId) of
        {ok, #?S3_USER{role_id = RoleId,
                       del = false}} ->
            find_all_with_role_1(Rest, [[{user_id, UserId},
                                         {role_id, RoleId},
                                         {access_key_id, AccessKeyId},
                                         {created_at, CretedAt}]|Acc]);
        _ ->

            find_all_with_role_1(Rest, Acc)
    end.


%% @doc Retrieve credential by user-id
%%
-spec(get_credential_by_user_id(UserId) ->
             {ok, [tuple()]} | not_found | {error, any()} when UserId::binary()).
get_credential_by_user_id(UserId) ->
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


%% @doc Retrieve checksum of the table
%%
-spec(checksum() ->
             {ok, non_neg_integer()} | not_found | {error, any()}).
checksum() ->
    case leo_s3_bucket_data_handler:find_all({mnesia, ?USER_CREDENTIAL_TABLE}) of
        {ok, RetL} ->
            {ok, erlang:crc32(term_to_binary(RetL))};
        _Error ->
            {ok, -1}
    end.
