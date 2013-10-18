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
%% Leo S3 Libs
%% @doc
%% @end
%%======================================================================
-module(leo_s3_libs).
-author('Yosuke Hara').

-include_lib("eunit/include/eunit.hrl").

-export([start/1, start/2, update_providers/1]).


%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
%% @doc Launch or create  Mnesia/ETS
%%
-spec(start(master | slave) ->
             ok).
start(Type) ->
    _ = application:start(crypto),
    ok = start_1(Type, [], 60),
    ok.

-spec(start(master | slave, list()) ->
             ok).
start(slave = Type, Options) ->
    _ = application:start(crypto),

    Provider = leo_misc:get_value('provider', Options, []),
    SyncInterval = leo_misc:get_value('sync_interval', Options, 60),
    ok = start_1(Type, Provider, SyncInterval),
    ok;

start(master = Type, _Options) ->
    _ = application:start(crypto),

    Provider = [],
    SyncInterval = 60,
    ok = start_1(Type, Provider, SyncInterval),
    ok.

%% @doc update_providers(slave only)
%%
-spec(update_providers(list()) ->
             ok).
update_providers(Provider) ->
    ok = leo_s3_auth:update_providers(Provider),
    ok = leo_s3_bucket:update_providers(Provider),
    ok = leo_s3_endpoint:update_providers(Provider),
    ok.

%%--------------------------------------------------------------------
%% INNER FUNCTION
%%--------------------------------------------------------------------
%% @doc Launch auth-lib, bucket-lib and endpoint-lib
%% @private
start_1(Type, Provider, SyncInterval) ->
    ok = leo_s3_auth:start(Type, Provider),
    ok = leo_s3_bucket:start(Type, Provider, SyncInterval),
    ok = leo_s3_endpoint:start(Type, Provider),
    ok.

