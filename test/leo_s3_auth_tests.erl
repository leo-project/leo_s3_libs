%%====================================================================
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
%% -------------------------------------------------------------------
%% Leo S3 Lib - Auth Test
%% @doc
%% @end
%%====================================================================
-module(leo_s3_auth_tests).
-author('Yosuke Hara').

-include("leo_s3_auth.hrl").
-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% TEST
%%--------------------------------------------------------------------
-ifdef(EUNIT).

-define(USER_ID, "leofs").


auth_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [{with, [T]} || T <- [fun mnesia_suite_/1%,
%%%                           fun ets_suite_/1,
%%%                           fun authenticate_0_/1,
%%%                           fun authenticate_1_/1,
%%%                           fun authenticate_2_/1,
%%%                           fun authenticate_3_/1,
%%%                           fun authenticate_4_/1,
%%%                           fun authenticate_5_/1,
%%%                           fun authenticate_6_/1,
%%%                           fun authenticate_7_/1
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
    %% inspect-1
    {error, not_initialized} = leo_s3_auth:gen_key(?USER_ID),

    %% inspect-2
    ok = leo_s3_auth:start(master, []),
    ok = leo_s3_auth:create_credential_table(ram_copies, [node()]),

    {ok, Keys} = leo_s3_auth:gen_key(?USER_ID),
    AccessKeyId     = proplists:get_value(access_key_id,     Keys),
    SecretAccessKey = proplists:get_value(secret_access_key, Keys),
    ?assertEqual(true, is_binary(AccessKeyId)),
    ?assertEqual(true, is_binary(SecretAccessKey)),
    ?assertEqual(20, size(AccessKeyId)),
    ?assertEqual(40, size(SecretAccessKey)),

    {ok, #credential{access_key_id     = AccessKeyId,
                     secret_access_key = SecretAccessKey,
                     user_id           = ?USER_ID
                    }} = leo_s3_libs_data_handler:lookup({mnesia, credentials}, AccessKeyId),

    1 = leo_s3_libs_data_handler:size({mnesia, credentials}),


    %% inspect-3 - for authentication
    ok = meck:new(leo_s3_bucket),
    ok = meck:expect(leo_s3_bucket, head,
                     fun(_AccessKeyId, _Bucket) ->
                             ok
                     end),

    SignParams0 = #sign_params{http_verb    = <<"GET">>,
                               content_md5  = <<>>,
                               content_type = <<>>,
                               date         = <<"Tue, 27 Mar 2007 19:36:42 +0000">>,
                               bucket       = <<"johnsmith">>,
                               uri          = <<"/photos/puppy.jpg">>},
    Signature0 = leo_s3_auth:get_signature(SecretAccessKey, SignParams0),
    Authorization0 = << <<"AWS ">>/binary, AccessKeyId/binary, <<":">>/binary, Signature0/binary >>,

    {ok, AccessKeyId} = leo_s3_auth:authenticate(Authorization0, SignParams0, false),
    {ok, Credential}  = leo_s3_auth:get_credential(AccessKeyId),
    ?assertEqual(AccessKeyId,     Credential#credential.access_key_id),
    ?assertEqual(SecretAccessKey, Credential#credential.secret_access_key),
    ?assertEqual("leofs",         Credential#credential.user_id),

    %% inspect-4 - for authentication
    Authorization1 = << <<"AWS ">>/binary, AccessKeyId/binary, <<":example">>/binary >>,
    {error, unmatch} = leo_s3_auth:authenticate(Authorization1, SignParams0, false),

    %% inspect-5 - for authentication
    _ = meck:unload(leo_s3_bucket),
    ok = meck:new(leo_s3_bucket),
    ok = meck:expect(leo_s3_bucket, head,
                     fun(_AccessKeyId, _Bucket) ->
                             not_found
                     end),
    {error, unmatch} = leo_s3_auth:authenticate(Authorization0, SignParams0, false),


    %% inspect-6 - for authentication
    SignParams1 = #sign_params{http_verb    = <<"GET">>,
                               content_md5  = <<>>,
                               content_type = <<>>,
                               date         = <<"Tue, 27 Mar 2007 19:36:42 +0000">>,
                               bucket       = <<"johnsmith">>,
                               uri          = <<"/">>},
    Signature1 = leo_s3_auth:get_signature(SecretAccessKey, SignParams1),
    Authorization2 = << <<"AWS ">>/binary, AccessKeyId/binary, <<":">>/binary, Signature1/binary >>,

    {ok, AccessKeyId} = leo_s3_auth:authenticate(Authorization2, SignParams1, false),


    %% inspect-7 - Retrieve owner by access key
    {ok,"leofs"} = leo_s3_auth:get_owner_by_access_key(binary_to_list(AccessKeyId)),
    not_found    = leo_s3_auth:get_owner_by_access_key([]),


    application:stop(mnesia),
    timer:sleep(250),
    ok.


%% @doc ETS
%%
%%%ets_suite_(_) ->
%%%    %% preparing
%%%    [] = os:cmd("epmd -daemon"),
%%%    {ok, Hostname} = inet:gethostname(),
%%%
%%%    Manager0 = list_to_atom("manager_0@" ++ Hostname),
%%%    net_kernel:start([Manager0, shortnames]),
%%%
%%%    {ok, Manager1} = slave:start_link(list_to_atom(Hostname), 'manager_1'),
%%%    true = rpc:call(Manager1, code, add_path, ["../deps/meck/ebin"]),
%%%
%%%
%%%    %% inspect-1
%%%    AccessKeyId     = "example_access_key_id",
%%%    SecretAccessKey = "example_secret_key",
%%%
%%%    ok = meck:new(leo_s3_bucket),
%%%    ok = meck:expect(leo_s3_bucket, head,
%%%                     fun(_AccessKeyId, _Bucket) ->
%%%                             ok
%%%                     end),
%%%
%%%    _  = rpc:call(Manager1, meck, unload, []),
%%%    ok = rpc:call(Manager1, meck, new,    [leo_s3_auth, [no_link]]),
%%%    ok = rpc:call(Manager1, meck, expect, [leo_s3_auth, get_credential,
%%%                                           fun(_AccessKeyId) ->
%%%                                                   {ok, #credential{access_key_id     = AccessKeyId,
%%%                                                                    secret_access_key = SecretAccessKey,
%%%                                                                    created_at        = 0}}
%%%                                           end]),
%%%
%%%    ok = leo_s3_auth:start(slave, [Manager1]),
%%%
%%%    SignParams = #sign_params{http_verb    = "GET",
%%%                              content_md5  = "",
%%%                              content_type = "",
%%%                              date         = "Tue, 27 Mar 2007 19:36:42 +0000",
%%%                              bucket       = "johnsmith",
%%%                              uri          = "/photos/puppy.jpg"},
%%%    Signature0 = leo_s3_auth:get_signature(SecretAccessKey, SignParams),
%%%    Authorization0 = "AWS" ++ " " ++ AccessKeyId ++ ":" ++ Signature0,
%%%    Authorization1 = "AWS" ++ " " ++ AccessKeyId ++ ":EXAMPLE",
%%%
%%%    {ok, AccessKeyId} = leo_s3_auth:authenticate(Authorization0, SignParams, false),
%%%    {error,unmatch} = leo_s3_auth:authenticate(Authorization1, SignParams, false),
%%%
%%%
%%%    {ok, #credential{access_key_id     = AccessKeyId,
%%%                     secret_access_key = SecretAccessKey
%%%                    }} = leo_s3_libs_data_handler:lookup({ets, credentials}, AccessKeyId),
%%%    1 = leo_s3_libs_data_handler:size({ets, credentials}),
%%%
%%%
%%%    %% inspect-4 - for authentication
%%%    _  = rpc:call(Manager1, meck, unload, []),
%%%    ok = rpc:call(Manager1, meck, new,    [leo_s3_auth, [no_link]]),
%%%    ok = rpc:call(Manager1, meck, expect, [leo_s3_auth, get_credential,
%%%                                           fun(_AccessKeyId) ->
%%%                                                   not_found
%%%                                           end]),
%%%    ets:delete_all_objects(credentials),
%%%
%%%    {error,unmatch} = leo_s3_auth:authenticate(Authorization0, SignParams, false),
%%%
%%%
%%%    %% teardown
%%%    slave:stop(Manager1),
%%%    net_kernel:stop(),
%%%    meck:unload(),
%%%    ok.
%%%
%%%
%%%%% @doc Authentication Header TEST
%%%%% @ref <http://docs.amazonwebservices.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader>
%%%%%
%%%-define(AWSAccessKeyId,     "AKIAIOSFODNN7EXAMPLE").
%%%-define(AWSSecretAccessKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").
%%%
%%%%% @doc Object GET
%%%authenticate_0_(_) ->
%%%    %% == PARAMS ==
%%%    %% AWSAccessKeyId:     AKIAIOSFODNN7EXAMPLE
%%%    %% AWSSecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
%%%
%%%    %% == REQUEST ==
%%%    %% GET /photos/puppy.jpg HTTP/1.1
%%%    %% Host: johnsmith.s3.amazonaws.com
%%%    %% Date: Tue, 27 Mar 2007 19:36:42 +0000
%%%    %%
%%%    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
%%%    %% bWq2s1WEIj+Ydj0vQ697zp+IXMU=
%%%
%%%    %% == StringToSign ==
%%%    %% GET\n
%%%    %% \n
%%%    %% \n
%%%    %% Tue, 27 Mar 2007 19:36:42 +0000\n
%%%    %% /johnsmith/photos/puppy.jpg
%%%
%%%    SignParams = #sign_params{http_verb    = "GET",
%%%                              content_md5  = "",
%%%                              content_type = "",
%%%                              date         = "Tue, 27 Mar 2007 19:36:42 +0000",
%%%                              bucket       = "johnsmith",
%%%                              uri          = "/photos/puppy.jpg"},
%%%
%%%    Ret = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams),
%%%    ?assertEqual("bWq2s1WEIj+Ydj0vQ697zp+IXMU=", Ret),
%%%    ok.
%%%
%%%
%%%%% @doc Object PUT
%%%authenticate_1_(_) ->
%%%    %% == PARAMS ==
%%%    %% PUT /photos/puppy.jpg HTTP/1.1
%%%    %% Content-Type: image/jpeg
%%%    %% Content-Length: 94328
%%%    %% Host: johnsmith.s3.amazonaws.com
%%%    %% Date: Tue, 27 Mar 2007 21:15:45 +0000
%%%    %%
%%%    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
%%%    %% MyyxeRY7whkBe+bq8fHCL/2kKUg=
%%%
%%%    %% == StringToSign ==
%%%    %% PUT\n
%%%    %% \n
%%%    %% image/jpeg\n
%%%    %% Tue, 27 Mar 2007 21:15:45 +0000\n
%%%    %% /johnsmith/photos/puppy.jpg
%%%
%%%    SignParams = #sign_params{http_verb    = "PUT",
%%%                              content_md5  = "",
%%%                              content_type = "image/jpeg",
%%%                              date         = "Tue, 27 Mar 2007 21:15:45 +0000",
%%%                              bucket       = "johnsmith",
%%%                              uri          = "/photos/puppy.jpg"},
%%%
%%%    Ret = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams),
%%%    ?assertEqual("MyyxeRY7whkBe+bq8fHCL/2kKUg=", Ret),
%%%    ok.
%%%
%%%
%%%%% @doc List
%%%authenticate_2_(_) ->
%%%    %% == PARAMS ==
%%%    %% GET /?prefix=photos&max-keys=50&marker=puppy HTTP/1.1
%%%    %% User-Agent: Mozilla/5.0
%%%    %% Host: johnsmith.s3.amazonaws.com
%%%    %% Date: Tue, 27 Mar 2007 19:42:41 +0000
%%%    %%
%%%    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
%%%    %% htDYFYduRNen8P9ZfE/s9SuKy0U=
%%%
%%%    %% == StringToSign ==
%%%    %% GET\n
%%%    %% \n
%%%    %% \n
%%%    %% Tue, 27 Mar 2007 19:42:41 +0000\n
%%%    %% /johnsmith/
%%%
%%%    SignParams = #sign_params{http_verb    = "GET",
%%%                              content_md5  = "",
%%%                              content_type = "",
%%%                              date         = "Tue, 27 Mar 2007 19:42:41 +0000",
%%%                              bucket       = "johnsmith",
%%%                              uri          = "/",
%%%                              query_str    = "?prefix=photos&max-keys=50&marker=puppy"
%%%                             },
%%%    Ret = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams),
%%%    ?assertEqual("htDYFYduRNen8P9ZfE/s9SuKy0U=", Ret),
%%%    ok.
%%%
%%%
%%%%% @doc Fetch
%%%authenticate_3_(_) ->
%%%    %% == PARAMS ==
%%%    %% GET /?acl HTTP/1.1
%%%    %% Host: johnsmith.s3.amazonaws.com
%%%    %%         Date: Tue, 27 Mar 2007 19:44:46 +0000
%%%    %%
%%%    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
%%%    %% c2WLPFtWHVgbEmeEG93a4cG37dM=
%%%
%%%    %% == StringToSign ==
%%%    %% GET\n
%%%    %% \n
%%%    %% \n
%%%    %% Tue, 27 Mar 2007 19:44:46 +0000\n
%%%    %% /johnsmith/?acl
%%%
%%%    SignParams = #sign_params{http_verb    = "GET",
%%%                              content_md5  = "",
%%%                              content_type = "",
%%%                              date         = "Tue, 27 Mar 2007 19:44:46 +0000",
%%%                              bucket       = "johnsmith",
%%%                              uri          = "/",
%%%                              query_str    = "?acl"
%%%                             },
%%%    Ret = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams),
%%%    ?assertEqual("c2WLPFtWHVgbEmeEG93a4cG37dM=", Ret),
%%%    ok.
%%%
%%%
%%%%% @doc Delete
%%%authenticate_4_(_) ->
%%%    %% NOTE: In this case the field for the actual 'Date' header is left blank in the StringToSign.
%%%
%%%    %% == PARAMS ==
%%%    %% DELETE /johnsmith/photos/puppy.jpg HTTP/1.1
%%%    %% User-Agent: dotnet
%%%    %% Host: s3.amazonaws.com
%%%    %% Date: Tue, 27 Mar 2007 21:20:27 +0000
%%%    %%
%%%    %% x-amz-date: Tue, 27 Mar 2007 21:20:26 +0000
%%%    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:9b2sXq0KfxsxHtdZkzx/9Ngqyh8=
%%%
%%%    %% == StringToSign ==
%%%    %% DELETE\n
%%%    %% \n
%%%    %% \n
%%%    %% x-amz-date:Tue, 27 Mar 2007 21:20:26 +0000\n
%%%    %% /johnsmith/photos/puppy.jpg
%%%
%%%    SignParams = #sign_params{http_verb    = "DELETE",
%%%                              content_md5  = "",
%%%                              content_type = "",
%%%                              date         = "Tue, 27 Mar 2007 21:20:27 +0000",
%%%                              bucket       = "johnsmith",
%%%                              uri          = "/photos/puppy.jpg",
%%%                              amz_headers  = [{"x-amz-date", "Tue, 27 Mar 2007 21:20:26 +0000"}]
%%%                             },
%%%    Ret = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams),
%%%    ?assertEqual("9b2sXq0KfxsxHtdZkzx/9Ngqyh8=", Ret),
%%%    ok.
%%%
%%%
%%%%% @doc Upload
%%%authenticate_5_(_) ->
%%%    %% == PARAMS ==
%%%    %% PUT /db-backup.dat.gz HTTP/1.1
%%%    %% User-Agent: curl/7.15.5
%%%    %% Host: static.johnsmith.net:8080
%%%    %% Date: Tue, 27 Mar 2007 21:06:08 +0000
%%%    %%
%%%    %% x-amz-acl: public-read
%%%    %% content-type: application/x-download
%%%    %% Content-MD5: 4gJE4saaMU4BqNR0kLY+lw==
%%%    %% X-Amz-Meta-ReviewedBy: joe@johnsmith.net
%%%    %% X-Amz-Meta-ReviewedBy: jane@johnsmith.net
%%%    %% X-Amz-Meta-FileChecksum: 0x02661779
%%%    %% X-Amz-Meta-ChecksumAlgorithm: crc32
%%%    %% Content-Disposition: attachment; filename=database.dat
%%%    %% Content-Encoding: gzip
%%%    %% Content-Length: 5913339
%%%    %%
%%%    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
%%%    %% ilyl83RwaSoYIEdixDQcA4OnAnc=
%%%
%%%    %% == StringToSign ==
%%%    %% PUT\n
%%%    %% 4gJE4saaMU4BqNR0kLY+lw==\n
%%%    %% application/x-download\n
%%%    %% Tue, 27 Mar 2007 21:06:08 +0000\n
%%%    %%
%%%    %% x-amz-acl:public-read\n
%%%    %% x-amz-meta-checksumalgorithm:crc32\n
%%%    %% x-amz-meta-filechecksum:0x02661779\n
%%%    %% x-amz-meta-reviewedby:joe@johnsmith.net,jane@johnsmith.net\n
%%%    %% /static.johnsmith.net/db-backup.dat.gz
%%%
%%%    SignParams1 = #sign_params{http_verb    = "PUT",
%%%                               content_md5  = "4gJE4saaMU4BqNR0kLY+lw==",
%%%                               content_type = "application/x-download",
%%%                               date         = "Tue, 27 Mar 2007 21:06:08 +0000",
%%%                               bucket       = "static.johnsmith.net",
%%%                               uri          = "/db-backup.dat.gz",
%%%                               amz_headers  = [{"x-amz-acl", "public-read"},
%%%                                               {"X-Amz-Meta-ReviewedBy", "joe@johnsmith.net"},
%%%                                               {"X-Amz-Meta-ReviewedBy", "jane@johnsmith.net"},
%%%                                               {"X-Amz-Meta-FileChecksum","0x02661779"},
%%%                                               {"X-Amz-Meta-ChecksumAlgorithm", "crc32"}]},
%%%    Ret1 = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams1),
%%%    ?assertEqual("ilyl83RwaSoYIEdixDQcA4OnAnc=", Ret1),
%%%    ok.
%%%
%%%
%%%%% @doc List All My Buckets
%%%authenticate_6_(_) ->
%%%    %% == PARAMS ==
%%%    %% GET / HTTP/1.1
%%%    %% Host: s3.amazonaws.com
%%%    %% Date: Wed, 28 Mar 2007 01:29:59 +0000
%%%    %%
%%%    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:qGdzdERIC03wnaRNKh6OqZehG9s=
%%%
%%%    %% == StringToSign ==
%%%    %% GET\n
%%%    %% \n
%%%    %% \n
%%%    %% Wed, 28 Mar 2007 01:29:59 +0000\n
%%%    %% /
%%%
%%%    SignParams = #sign_params{http_verb    = "GET",
%%%                              content_md5  = "",
%%%                              content_type = "",
%%%                              date         = "Wed, 28 Mar 2007 01:29:59 +0000",
%%%                              bucket       = "",
%%%                              uri          = "/",
%%%                              amz_headers  = []},
%%%    Ret = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams),
%%%    ?assertEqual("qGdzdERIC03wnaRNKh6OqZehG9s=", Ret),
%%%    ok.
%%%
%%%
%%%%% @doc Unicode Keys
%%%authenticate_7_(_) ->
%%%    %% == PARAMS ==
%%%    %% GET /dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re HTTP/1.1
%%%    %% Host: s3.amazonaws.com
%%%    %% Date: Wed, 28 Mar 2007 01:49:49 +0000
%%%    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:DNEZGsoieTZ92F3bUfSPQcbGmlM=
%%%
%%%    %% == StringToSign ==
%%%    %% GET\n
%%%    %% \n
%%%    %% \n
%%%    %% Wed, 28 Mar 2007 01:49:49 +0000\n
%%%    %% /dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re
%%%
%%%    SignParams = #sign_params{http_verb    = "GET",
%%%                              content_md5  = "",
%%%                              content_type = "",
%%%                              date         = "Wed, 28 Mar 2007 01:49:49 +0000",
%%%                              bucket       = "",
%%%                              uri          = "/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re",
%%%                              amz_headers  = []},
%%%    Ret = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams),
%%%    ?assertEqual("DNEZGsoieTZ92F3bUfSPQcbGmlM=", Ret),
%%%    ok.

-endif.
