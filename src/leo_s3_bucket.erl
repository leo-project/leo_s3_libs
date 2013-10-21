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
%% Leo S3 Libs - Bucket
%% @doc
%% @end
%%======================================================================
-module(leo_s3_bucket).

-author('Yosuke Hara').

-include("leo_s3_bucket.hrl").
-include("leo_s3_user.hrl").
-include("leo_s3_libs.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([start/3, create_bucket_table/2, is_valid_bucket/1,
         update_providers/1,
         find_bucket_by_name/1, find_bucket_by_name/2,
         find_buckets_by_id/1, find_buckets_by_id/2, find_all/0,
         find_all_including_owner/0,
         get_acls/1, update_acls/3,
         update_acls2private/2, update_acls2public_read/2,
         update_acls2public_read_write/2, update_acls2authenticated_read/2,
         put/2, put/3, delete/2, head/2, head/4]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
%% @doc Launch a lib
%%
-spec(start(atom(), ets | mnesia, pos_integer()) ->
             ok).
start(slave = Type, Provider, SyncInterval) ->
    catch ets:new(?BUCKET_TABLE, [named_table, ordered_set, public, {read_concurrency, true}]),
    catch ets:new(?BUCKET_INFO,  [named_table, set,         public, {read_concurrency, true}]),

    case Provider of
        [] ->
            void;
        _ ->
            ok = setup(Type, ets, Provider, SyncInterval)
    end,
    ok;

start(master = Type, _Provider, SyncInterval) ->
    catch ets:new(?BUCKET_INFO,  [named_table, set, public, {read_concurrency, true}]),
    ok = setup(Type, mnesia, [], SyncInterval),
    ok.


%% @doc update_providers(slave only)
%%
-spec(update_providers(list()) ->
             ok).
update_providers(Provider) ->
    true = ets:insert(?BUCKET_INFO, {1, #bucket_info{type = slave,
                                                     db   = ets,
                                                     provider = Provider}}),
    ok.


%% Create bucket table(mnesia)
%%
-spec(create_bucket_table(ram_copies|disc|copies, list()) ->
             ok).
create_bucket_table(Mode, Nodes) ->
    _ = application:start(mnesia),
    {atomic, ok} =
        mnesia:create_table(
          ?BUCKET_TABLE,
          [{Mode, Nodes},
           {type, set},
           {record_name, bucket},
           {attributes, record_info(fields, bucket)}
          ]),
    ok.


%% @doc Retrieve buckets by AccessKey
%%
-spec(find_buckets_by_id(binary()) ->
             {ok, list()} | {error, any()}).
find_buckets_by_id(AccessKey) ->
    case get_info() of
        %% Retrieve value from local-mnesia.
        {ok, #bucket_info{db = DB}} when DB == mnesia ->
            leo_s3_bucket_data_handler:lookup({DB, ?BUCKET_TABLE}, AccessKey);

        %% Inquiry bucket-checksum to manager-nodes.
        %% If local-checksum equal provider's checksum, then return local-list,
        %% but local-checksum does NOT equal provider's checksum, then return provider's list.
        {ok, #bucket_info{db = DB, provider = Provider}} when DB == ets ->
            find_buckets_by_id_1(AccessKey, DB, Provider);
        Error ->
            Error
    end.

-spec(find_buckets_by_id(binary(), string()) ->
             {ok, list()} | {ok, match} | {error, any()}).
find_buckets_by_id(AccessKey, Checksum0) ->
    case get_info() of
        {ok, #bucket_info{db = DB}} when DB == mnesia ->
            case find_buckets_by_id(AccessKey) of
                {ok, Value} ->
                    case erlang:crc32(term_to_binary(Value)) of
                        Checksum0 ->
                            {ok, match};
                        _ ->
                            {ok, Value}
                    end;
                Error ->
                    Error
            end;
        {ok, #bucket_info{db = DB}} when DB == ets ->
            {error, ignored};
        Error ->
            Error
    end.


%% @doc Retrieve a bucket by bucket-name
%%
-spec(find_bucket_by_name(binary()) ->
             {ok, #bucket{}} | {error, any()}).
find_bucket_by_name(Bucket) ->
    case get_info() of
        %% Retrieve value from local-mnesia.
        {ok, #bucket_info{db = DB}} when DB == mnesia ->
            leo_s3_bucket_data_handler:find_by_name({DB, ?BUCKET_TABLE}, <<>>, Bucket, false);
        %% Inquiry bucket-checksum to manager-nodes.
        %% If local-checksum equal provider's checksum, then return local-list,
        %% but local-checksum does NOT equal provider's checksum, then return provider's list.
        {ok, #bucket_info{db = DB, provider = Provider}} when DB == ets ->
            find_bucket_by_name_1(Bucket, DB, Provider);
        Error ->
            Error
    end.

-spec(find_bucket_by_name(binary(), integer()) ->
             {ok, #bucket{}} | {ok, match} | {error, any()}).
find_bucket_by_name(Bucket, LastModifiedAt) ->
    case get_info() of
        {ok, #bucket_info{db = DB}} when DB == mnesia ->
            case find_bucket_by_name(Bucket) of
                {ok, #bucket{last_modified_at = OrgLastModifiedAt} = Value} ->
                    case LastModifiedAt == OrgLastModifiedAt of
                        true ->
                            {ok, match};
                        false ->
                            {ok, Value}
                    end;
                Error ->
                    Error
            end;
        {ok, #bucket_info{db = DB}} when DB == ets ->
            {error, ignored};
        Error ->
            Error
    end.


%% @doc Retrieve all buckets
%%
-spec(find_all() ->
             {ok, list()} | {error, any()}).
find_all() ->
    case get_info() of
        {ok, #bucket_info{db = DB}} ->
            leo_s3_bucket_data_handler:find_all({DB, ?BUCKET_TABLE});
        Error ->
            Error
    end.


%% @doc Retrieve all buckets and owner
%%
-spec(find_all_including_owner() ->
             {ok, list()} | {error, any()}).
find_all_including_owner() ->
    case find_all() of
        {ok, Buckets} ->
            Ret = lists:map(fun(#bucket{name       = Name,
                                        access_key = AccessKeyId,
                                        created_at = CreatedAt}) ->
                                    Owner1 = case leo_s3_user:find_by_access_key_id(AccessKeyId) of
                                                 {ok, Owner0} -> Owner0;
                                                 _ -> #user_credential{}
                                             end,
                                    {Name, Owner1, CreatedAt}
                            end, Buckets),
            case Ret of
                [] -> not_found;
                _  -> {ok, Ret}
            end;
        Error ->
            Error
    end.


%% @doc put a bucket.
%%
-spec(put(binary(), binary()) ->
             ok | {error, any()}).
put(AccessKey, Bucket) ->
    case get_info() of
        {ok, #bucket_info{type = slave,
                          db   = DB,
                          provider = Provider}} ->
            case leo_s3_auth:has_credential(Provider, AccessKey) of
                true ->
                    case rpc_call(Provider, put, [AccessKey, Bucket]) of
                        true ->
                            put(AccessKey, Bucket, DB);
                        false ->
                            {error, not_stored}
                    end;
                false ->
                    {error, invalid_access}
            end;
        {ok, #bucket_info{type = master, db = DB}} ->
            case leo_s3_auth:has_credential(AccessKey) of
                true ->
                    put(AccessKey, Bucket, DB);
                false ->
                    {error, invalid_access}
            end;
        Error ->
            Error
    end.

-spec(put(binary(), binary(), ets | mnesia) ->
             ok | {error, any()}).
put(AccessKey, Bucket, DB) ->
    Res = head(AccessKey, Bucket),

    case (Res == ok orelse Res == not_found) of
        true ->
            BucketStr = cast_binary_to_str(Bucket),
            case is_valid_bucket(BucketStr) of
                ok ->
                    %% ACL is set to private(default)
                    ACLs = [#bucket_acl_info{user_id     = AccessKey,
                                             permissions = [full_control]}],
                    Now = leo_date:now(),
                    leo_s3_bucket_data_handler:insert({DB, ?BUCKET_TABLE},
                                                      #bucket{name       = Bucket,
                                                              access_key = AccessKey,
                                                              acls       = ACLs,
                                                              created_at = Now,
                                                              last_modified_at = Now});
                Error ->
                    Error
            end;
        false ->
            {error, already_has}
    end.


%% @doc delete a bucket.
%%
-spec(delete(binary(), binary()) ->
             ok | {error, any()}).
delete(AccessKey, Bucket) ->
    case get_info() of
        {ok, #bucket_info{type = slave,
                          db   = DB,
                          provider = Provider}} ->
            case rpc_call(Provider, delete, [AccessKey, Bucket]) of
                true ->
                    delete(AccessKey, Bucket, DB);
                false ->
                    {error, not_deleted}
            end;
        {ok, #bucket_info{type = master, db = DB}} ->
            delete(AccessKey, Bucket, DB);
        Error ->
            Error
    end.

-spec(delete(binary(), binary(), ets | mnesia) ->
             ok | {error, any()}).
delete(AccessKey, Bucket, DB) ->
    leo_s3_bucket_data_handler:delete({DB, ?BUCKET_TABLE},
                                      #bucket{name = Bucket,
                                              access_key = AccessKey}).


%% @doc update acls in a bukcet-property
%%
-spec(update_acls(binary(), binary(), acls()) ->
             ok | {error, any()}).
update_acls(AccessKey, Bucket, ACLs) ->
    case get_info() of
        {ok, #bucket_info{type = slave,
                          db   = DB,
                          provider = Provider}} ->
            case leo_s3_auth:has_credential(Provider, AccessKey) of
                true ->
                    case rpc_call(Provider, update_acls, [AccessKey, Bucket, ACLs]) of
                        true ->
                            update_acls(AccessKey, Bucket, ACLs, DB);
                        false ->
                            {error, not_stored}
                    end;
                false ->
                    {error, invalid_access}
            end;
        {ok, #bucket_info{type = master, db = DB}} ->
            case leo_s3_auth:has_credential(AccessKey) of
                true ->
                    update_acls(AccessKey, Bucket, ACLs, DB);
                false ->
                    {error, invalid_access}
            end;
        Error ->
            Error
    end.

-spec(update_acls(binary(), binary(), acls(), ets | mnesia) ->
             ok | {error, any()}).
update_acls(AccessKey, Bucket, ACLs, DB) ->
    BucketStr = cast_binary_to_str(Bucket),
    case is_valid_bucket(BucketStr) of
        ok ->
            Now = leo_date:now(),
            leo_s3_bucket_data_handler:insert({DB, ?BUCKET_TABLE},
                                              #bucket{name       = Bucket,
                                                      access_key = AccessKey,
                                                      acls       = ACLs,
                                                      last_synchroized_at = Now,
                                                      last_modified_at    = Now});
        Error ->
            Error
    end.


%% @doc update acls to 'private'
%%
-spec(update_acls2private(binary(), #bucket{}) ->
             ok | {error, any()}).
update_acls2private(AccessKey, Bucket) ->
    ACLs = [#bucket_acl_info{user_id     = AccessKey,
                             permissions = [full_control]}],
    update_acls(AccessKey, Bucket, ACLs).


%% @doc update acls to 'public_read'
%%
-spec(update_acls2public_read(binary(), #bucket{}) ->
             ok | {error, any()}).
update_acls2public_read(AccessKey, Bucket) ->
    ACLs = [#bucket_acl_info{user_id     = ?GRANTEE_ALL_USER,
                             permissions = [read]}],
    update_acls(AccessKey, Bucket, ACLs).


%% @doc update acls to 'public_read_write'
%%
-spec(update_acls2public_read_write(binary(), #bucket{}) ->
             ok | {error, any()}).
update_acls2public_read_write(AccessKey, Bucket) ->
    ACLs = [#bucket_acl_info{user_id     = ?GRANTEE_ALL_USER,
                             permissions = [read, write]}],
    update_acls(AccessKey, Bucket, ACLs).


%% @doc update acls to 'authenticated_read'
%%
-spec(update_acls2authenticated_read(binary(), #bucket{}) ->
             ok | {error, any()}).
update_acls2authenticated_read(AccessKey, Bucket) ->
    ACLs = [#bucket_acl_info{user_id     = ?GRANTEE_AUTHENTICATED_USER,
                             permissions = [read]}],
    update_acls(AccessKey, Bucket, ACLs).


%% @doc Retrive acls by a bucket
%%
-spec(get_acls(binary()) ->
             {ok, acls() }| not_found | {error, forbidden} | {error, any()}).
get_acls(Bucket) ->
    case get_info() of
        {ok, #bucket_info{db = DB,
                          sync_interval = SyncInterval,
                          type = Type}} ->
            Now = leo_date:now(),
            case leo_s3_bucket_data_handler:find_by_name(
                   {DB, ?BUCKET_TABLE}, <<>>, Bucket, false) of
                {ok, #bucket{acls = ACLs,
                             last_synchroized_at = LastSynchronizedAt}}
                  when (Now - LastSynchronizedAt) < SyncInterval ->
                    %% valid local record
                    {ok, ACLs};
                {ok, #bucket{acls = _ACLs}} ->
                    %% to be synced with manager's record
                    case find_bucket_by_name(Bucket) of
                        {ok, #bucket{acls = NewACLs}} ->
                            {ok, NewACLs};
                        Error ->
                            Error
                    end;
                not_found when Type == slave->
                    case find_bucket_by_name(Bucket) of
                        {ok, #bucket{acls = NewACLs}} ->
                            {ok, NewACLs};
                        Error ->
                            Error
                    end;
                Other ->
                    Other
            end;
        Error ->
            Error
    end.


%% @doc Is exist a bucket into the db
%%
-spec(head(binary(), binary()) ->
             ok | not_found | {error, forbidden} | {error, any()}).
head(AccessKey, Bucket) ->
    case get_info() of
        {ok, #bucket_info{db       = DB,
                          type     = Type,
                          provider = Provider}} ->
            case leo_s3_bucket_data_handler:find_by_name(
                   {DB, ?BUCKET_TABLE}, AccessKey, Bucket) of
                {ok, _Value0} ->
                    ok;
                not_found when Type == slave->
                    case head(AccessKey, Bucket, DB, Provider) of
                        {ok, _} ->
                            ok;
                        Error ->
                            Error
                    end;
                Other ->
                    Other
            end;
        Error ->
            Error
    end.

head(AccessKey, Bucket, DB, Provider) ->
    case find_buckets_by_id_1(AccessKey, DB, Provider) of
        {ok, _} ->
            Ret = leo_s3_bucket_data_handler:find_by_name(
                    {DB, ?BUCKET_TABLE}, AccessKey, Bucket),
            Ret;
        Error ->
            Error
    end.


%%--------------------------------------------------------------------
%% INNER FUNCTIONS
%%--------------------------------------------------------------------
%% @doc Setup
%% @private
-spec(setup(master|slave, ets|mnesia, list(), pos_integer()) ->
             ok).
setup(Type, DB, Provider, SyncInterval) ->
    true = ets:insert(?BUCKET_INFO, {1, #bucket_info{type = Type,
                                                     db   = DB,
                                                     provider = Provider,
                                                     sync_interval= SyncInterval}}),
    ok.


%% @doc Retrieve database-type.
%% @private
-spec(get_info() ->
             {ok, #bucket{}} | {error, any()}).
get_info() ->
    case ets:lookup(?BUCKET_INFO, 1) of
        [{_, Info}|_] ->
            {ok, Info};
        [] ->
            {error, not_initialized};
        {_, Cause} ->
            {error, Cause}
    end.


%% @doc Insert values into the mnesia.
%%
-spec(put_all_values(ets | mnesia, list()) ->
             ok).
put_all_values(_, []) ->
    ok;
put_all_values(DB, [H|T]) ->
    leo_s3_bucket_data_handler:insert({DB, ?BUCKET_TABLE}, H),
    put_all_values(DB, T).


%% @doc Retrieve buckets by id
%% @private
-spec(find_buckets_by_id_1(binary(), ets|mnesia, list()) ->
             {ok, list()} | {error, any()}).
find_buckets_by_id_1(AccessKey, DB, Providers) ->
    {Value0, CRC} = case leo_s3_bucket_data_handler:lookup(
                           {DB, ?BUCKET_TABLE}, AccessKey) of
                        {ok, Val} ->
                            {Val, erlang:crc32(term_to_binary(Val))};
                        _Other ->
                            {[], -1}
                    end,

    Ret = lists:foldl(
            fun(Node, []) ->
                    find_buckets_by_id_2(AccessKey, DB, Node, Value0, CRC);
               (Node, {error, _Cause}) ->
                    find_buckets_by_id_2(AccessKey, DB, Node, Value0, CRC);
               (_Node, Acc) ->
                    Acc
            end, [], Providers),
    Ret.

-spec(find_buckets_by_id_2(binary(), ets|mnesia, atom(), list(), integer()) ->
             {ok, list()} | {error, any()}).
find_buckets_by_id_2(AccessKey, DB, Node, Value0, CRC) ->
    RPCKey = rpc:async_call(Node, leo_s3_bucket, find_buckets_by_id,
                            [AccessKey, CRC]),
    Ret = case rpc:nb_yield(RPCKey, ?DEF_REQ_TIMEOUT) of
              {value, {ok, match}} when Value0 == [] ->
                  not_found;
              {value, {ok, match}} when Value0 /= [] ->
                  {ok, Value0};
              {value, {ok, Value1}} ->
                  lists:foreach(fun(Bucket) ->
                                        leo_s3_bucket_data_handler:delete({DB, ?BUCKET_TABLE}, Bucket)
                                end, Value0),
                  ok = put_all_values(ets, Value1),
                  {ok, Value1};
              {value, not_found} ->
                  not_found;
              {value, {error, Cause}} ->
                  {error, Cause};
              {value, {badrpc, Cause}} ->
                  {error, Cause};
              {'EXIT', Cause} ->
                  {error, Cause}
          end,
    Ret.


%% @doc Retrieve buckets by name
%% @private
-spec(find_bucket_by_name_1(binary(), ets|mnesia, list()) ->
             {ok, list()} | {error, any()}).
find_bucket_by_name_1(Bucket, DB, Providers) ->
    Value0 = case leo_s3_bucket_data_handler:find_by_name(
                    {DB, ?BUCKET_TABLE}, <<>>, Bucket, false) of
                 {ok, Val} ->
                     Val;
                 _Other ->
                     []
             end,

    Ret = lists:foldl(
            fun(Node, []) ->
                    find_bucket_by_name_2(Bucket, DB, Node, Value0);
               (Node, {error, _Cause}) ->
                    find_bucket_by_name_2(Bucket, DB, Node, Value0);
               (_Node, Acc) ->
                    Acc
            end, [], Providers),
    Ret.

-spec(find_bucket_by_name_2(binary(), ets|mnesia, atom(), list()) ->
             {ok, list()} | {error, any()}).
find_bucket_by_name_2(Bucket, DB, Node, Value0) ->
    LastModifiedAt = case Value0 == [] of
                         true ->
                             0;
                         false ->
                             Value0#bucket.last_modified_at
                     end,
    RPCKey = rpc:async_call(Node, leo_s3_bucket, find_bucket_by_name,
                            [Bucket, LastModifiedAt]),
    Ret = case rpc:nb_yield(RPCKey, ?DEF_REQ_TIMEOUT) of
              {value, {ok, match}} when Value0 == [] ->
                  not_found;
              {value, {ok, match}} when Value0 /= [] ->
                  {ok, Value0};
              {value, {ok, Value1}} ->
                  NewBucketVal = Value1#bucket{last_synchroized_at = leo_date:now()},
                  catch leo_s3_bucket_data_handler:delete({DB, ?BUCKET_TABLE}, Value0),
                  leo_s3_bucket_data_handler:insert({DB, ?BUCKET_TABLE}, NewBucketVal),
                  {ok, NewBucketVal};
              {value, not_found} ->
                  not_found;
              {value, {error, Cause}} ->
                  {error, Cause};
              {value, {badrpc, Cause}} ->
                  {error, Cause};
              {'EXIT', Cause} ->
                  {error, Cause}
          end,
    Ret.


%% @doc Communicate remote node(s)
%% @private
-spec(rpc_call(list(), atom(), list()) ->
             true | false).
rpc_call(Provider, Function, Args) ->
    Ret = lists:foldl(
            fun(Node, false) ->
                    RPCKey = rpc:async_call(Node, leo_s3_bucket, Function, Args),
                    case rpc:nb_yield(RPCKey, ?DEF_REQ_TIMEOUT) of
                        {value, ok} -> true;
                        _Error      -> false
                    end;
               (_, true) ->
                    true
            end, false, Provider),
    Ret.


%% @doc validate a string if which consits of digit chars
%% @private
is_only_digits(String) ->
    [Char || Char <- String, Char < $0 orelse Char > $9] == [].


%% @doc validate a bucket name
%% @private
-spec(is_valid_bucket(string()) ->
             ok | {error, badarg}).
is_valid_bucket(Bucket) when is_list(Bucket), length(Bucket) < 3 ->
    {error, badarg};
is_valid_bucket(Bucket) when is_list(Bucket), length(Bucket) > 62 ->
    {error, badarg};
is_valid_bucket([$.|_]) ->
    {error, badarg};
is_valid_bucket([H|T]) ->
    is_valid_bucket(T, H, [H], true).

is_valid_bucket([], LastChar, _LastLabel, _OnlyDigit) when LastChar == $. ->
    {error, badarg};
is_valid_bucket([], _LastChar, LastLabel, true) ->
    case is_only_digits(LastLabel) of
        true  -> {error, badarg};
        false -> ok
    end;
is_valid_bucket([], _LastChar, _LastLabel, _OnlyDigit) ->
    ok;
is_valid_bucket([$.|_], $., _LastLabel, _OnlyDigit) ->
    {error, badarg};
is_valid_bucket([$.|T], _LastChar, _LastLabel, false) ->
    is_valid_bucket(T, $., [], false);
is_valid_bucket([$.|T], _LastChar, LastLabel, true) ->
    case is_only_digits(LastLabel) of
        true  -> is_valid_bucket(T, $., [], true);
        false -> is_valid_bucket(T, $., [], false)
    end;
is_valid_bucket([H|T], _LastChar, LastLabel, OnlyDigit) when (H >= $a andalso H =< $z) orelse
                                                             (H >= $0 andalso H =< $9) orelse
                                                             H == $- ->
    is_valid_bucket(T, H, LastLabel ++ [H], OnlyDigit);
is_valid_bucket([_|_], _LastChar, _LastLabel, _OnlyDigit) ->
    {error, badarg}.


%% @doc exchange value type from binary to string
%% @private
cast_binary_to_str(Bucket) ->
    case is_binary(Bucket) of
        true  -> binary_to_list(Bucket);
        false -> Bucket
    end.
