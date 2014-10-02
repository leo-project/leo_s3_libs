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
%% Leo S3 Libs
%% @doc The s3-libs API
%% @reference https://github.com/leo-project/leo_s3_libs/blob/master/src/leo_s3_libs.erl
%% @end
%%======================================================================
-module(leo_s3_libs).
-author('Yosuke Hara').

-include("leo_s3_bucket.hrl").
-include("leo_s3_libs.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([start/1, start/2,
         update_providers/1, get_checksums/0]).


%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
%% @doc Launch or create  Mnesia/ETS
%%
-spec(start(Role) ->
             ok when Role::master|slave).
start(Type) ->
    _ = application:start(crypto),
    ok = start_1(Type, [], ?DEF_BUCKET_PROP_SYNC_INTERVAL),
    ok.

-spec(start(Role, Options) ->
             ok when Role::master|slave,
                     Options::list()).
start(slave = Type, Options) ->
    _ = application:start(crypto),

    Provider = leo_misc:get_value('provider', Options, []),
    BucketPropSyncInterval = leo_misc:get_value(
                               'bucket_prop_sync_interval', Options,
                               ?DEF_BUCKET_PROP_SYNC_INTERVAL),
    ok = start_1(Type, Provider, BucketPropSyncInterval),
    ok;

start(master = Type, _Options) ->
    _ = application:start(crypto),

    BucketPropSyncInterval = ?DEF_BUCKET_PROP_SYNC_INTERVAL,
    ok = start_1(Type, [], BucketPropSyncInterval),
    ok.


%% @doc update_providers(slave only)
%%
-spec(update_providers(Provider) ->
             ok when Provider::list()).
update_providers(Provider) ->
    ok = leo_s3_auth:update_providers(Provider),
    ok = leo_s3_bucket:update_providers(Provider),
    ok = leo_s3_endpoint:update_providers(Provider),
    ok.


%% @doc update_providers(slave only)
%%
-spec(get_checksums() ->
             {ok, #s3_tbls_checksum{}}).
get_checksums() ->
    {ok, C1} = leo_s3_auth:checksum(),
    {ok, C2} = leo_s3_bucket:checksum(),
    {ok, C3} = leo_s3_user:checksum(),
    {ok, C4} = leo_s3_user_credential:checksum(),
    {ok, #s3_tbls_checksum{auth       = C1,
                           bucket     = C2,
                           user       = C3,
                           credential = C4}}.


%%--------------------------------------------------------------------
%% INNER FUNCTION
%%--------------------------------------------------------------------
%% @doc Launch auth-lib, bucket-lib and endpoint-lib
%% @private
start_1(Type, Provider, BucketPropSyncInterval) ->
    ok = leo_s3_auth:start(Type, Provider),
    ok = leo_s3_bucket:start(Type, Provider, BucketPropSyncInterval),
    ok = leo_s3_endpoint:start(Type, Provider),
    ok.

