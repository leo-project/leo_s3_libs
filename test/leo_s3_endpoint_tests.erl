%%====================================================================
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
%% -------------------------------------------------------------------
%% Leo S3 Lib - Auth Test
%% @doc
%% @end
%%====================================================================
-module(leo_s3_endpoint_tests).
-author('Yosuke Hara').

-include("leo_s3_endpoint.hrl").
-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% TEST
%%--------------------------------------------------------------------
-ifdef(EUNIT).

-define(USER_ID, <<"leofs">>).


auth_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [{with, [T]} || T <- [fun mnesia_suite_/1,
                           fun ets_suite_/1
                          ]]}.

setup() ->
    application:start(crypto),
    ok.

teardown(_) ->
    application:stop(crypto),
    ok.

%% @doc Mnesia
%%
mnesia_suite_(_) ->
    ok = leo_s3_endpoint:start(master, []),

    ok = leo_s3_endpoint:create_table(ram_copies, [node()]),
    not_found = leo_s3_endpoint:get_endpoints(),

    ok = leo_s3_endpoint:set_endpoint(<<"photo.leofs.org">>),
    ok = leo_s3_endpoint:set_endpoint(<<"backup.leofs.org">>),

    {ok, EndPoints0} = leo_s3_endpoint:get_endpoints(),
    ?assertEqual(2, length(EndPoints0)),

    ok = leo_s3_endpoint:delete_endpoint(<<"photo.leofs.org">>),
    {ok, EndPoints1} = leo_s3_endpoint:get_endpoints(),
    ?assertEqual(1, length(EndPoints1)),

    {ok, Checksum} = leo_s3_endpoint:checksum(),
    ?assertEqual(true, Checksum > 0),

    application:stop(mnesia),
    timer:sleep(250),
    ok.


%% @doc ETS
%%
ets_suite_(_) ->
    %% preparing
    [] = os:cmd("epmd -daemon"),
    {ok, Hostname} = inet:gethostname(),

    Manager0 = list_to_atom("manager_0@" ++ Hostname),
    net_kernel:start([Manager0, shortnames]),

    {ok, Manager1} = slave:start_link(list_to_atom(Hostname), 'manager_1'),
    true = rpc:call(Manager1, code, add_path, ["../deps/meck/ebin"]),

    %% inspect
    ok = leo_s3_endpoint:start(slave, [Manager1]),
    Res0 = leo_s3_endpoint:get_endpoints(),
    ?assertEqual({error, not_found}, Res0),

    ok = rpc:call(Manager1, meck, new,    [leo_s3_endpoint, [no_link, non_strict]]),
    ok = rpc:call(Manager1, meck, expect, [leo_s3_endpoint, get_endpoints,
                                           fun() ->
                                                   {ok, [#endpoint{endpoint="photo.leofs.org"},
                                                         #endpoint{endpoint="backup.leofs.org"}]}
                                           end]),

    {ok, Res1} = leo_s3_endpoint:get_endpoints(),
    ?assertEqual(2, length(Res1)),

    ok = leo_s3_endpoint:delete_endpoint("photo.leofs.org"),
    {ok, EndPoints1} = leo_s3_endpoint:get_endpoints(),
    ?assertEqual(1, length(EndPoints1)),

    %% update_providers
    Manager2 = list_to_atom("manager_2@" ++ Hostname),
    ok = leo_s3_endpoint:update_providers([Manager2]),


    %% teardown
    slave:stop(Manager1),
    net_kernel:stop(),
    meck:unload(),
    ok.

-endif.
