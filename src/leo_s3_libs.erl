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
%% Leo Libs
%% @doc
%% @end
%%======================================================================
-module(leo_s3_libs).
-author('Yosuke Hara').

-include_lib("eunit/include/eunit.hrl").

-export([start/2]).


%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
%% @doc Launch or create  Mnesia/ETS
%%
-spec(start(master | slave, list()) ->
             ok).
start(slave = Type, Options) ->
    _ = application:start(crypto),

    Provider = proplists:get_value('provider', Options, []),
    ok = start_1(Type, Provider),
    ok;

start(master = Type, _Options) ->
    _ = application:start(crypto),

    Provider = [],
    ok = start_1(Type, Provider),
    ok.



%% @doc Launch auth-lib, bucket-lib and endpoint-lib
%% @private
start_1(Type, Provider) ->
    ok = leo_s3_auth:start(Type, Provider),
    ok = leo_s3_bucket:start(Type, Provider),
    ok = leo_s3_endpoint:start(Type, Provider),
    ok.

