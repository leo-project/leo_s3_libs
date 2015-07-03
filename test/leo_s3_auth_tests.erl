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
-module(leo_s3_auth_tests).
-author('Yosuke Hara').

-include("leo_s3_auth.hrl").
-include("leo_s3_user.hrl").
-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% TEST
%%--------------------------------------------------------------------
-ifdef(EUNIT).

-define(USER_ID, <<"leofs">>).


auth_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [{with, [T]} || T <- [fun mnesia_suite_/1,
                           fun ets_suite_/1,
                           fun authenticate_0_/1,
                           fun authenticate_1_/1,
                           fun authenticate_2_/1,
                           fun authenticate_3_/1,
                           fun authenticate_4_/1,
                           fun authenticate_5_/1,
                           fun authenticate_6_/1,
                           fun authenticate_7_/1,
                           fun authenticate_8_/1,
                           fun authenticate_9_/1,
                           fun authenticate_10_/1,
                           fun authenticate_v4_1/1,
                           fun authenticate_v4_2/1,
                           fun authenticate_v4_3/1,
                           fun authenticate_v4_4/1,
                           fun authenticate_v4_5/1,
                           fun authenticate_v4_6/1
                          ]]}.

setup() ->
    application:start(crypto),
    ok.

teardown(_) ->
    application:stop(crypto),
    meck:unload(),
    ok.

%% @doc Mnesia
%%
mnesia_suite_(_) ->
    %% inspect-1
    {error, not_initialized} = leo_s3_auth:create_key(?USER_ID),

    %% inspect-2
    ok = meck:new(leo_s3_user, [non_strict]),
    ok = meck:expect(leo_s3_user, find_by_id,
                     fun(_) ->
                             not_found
                     end),

    ok = leo_s3_auth:start(master, []),
    ok = leo_s3_auth:create_table(ram_copies, [node()]),

    {ok, Keys} = leo_s3_auth:create_key(?USER_ID),
    AccessKeyId     = proplists:get_value(access_key_id,     Keys),
    SecretAccessKey = proplists:get_value(secret_access_key, Keys),

    ?assertEqual(true, is_binary(AccessKeyId)),
    ?assertEqual(true, is_binary(SecretAccessKey)),
    ?assertEqual(20, size(AccessKeyId)),
    ?assertEqual(40, size(SecretAccessKey)),

    {ok, #credential{access_key_id     = AccessKeyId,
                     secret_access_key = SecretAccessKey}} =
        leo_s3_libs_data_handler:lookup({mnesia, leo_s3_credentials}, AccessKeyId),

    1 = leo_s3_libs_data_handler:size({mnesia, leo_s3_credentials}),


    %% inspect-3 - for authentication
    ok = meck:new(leo_s3_bucket, [non_strict]),
    ok = meck:expect(leo_s3_bucket, head,
                     fun(_AccessKeyId, _Bucket) ->
                             ok
                     end),
    _ = meck:unload(leo_s3_user),
    ok = meck:new(leo_s3_user, [non_strict]),
    ok = meck:expect(leo_s3_user, find_by_id,
                     fun(_) ->
                             {ok, #?S3_USER{}}
                     end),
    ok = meck:new(leo_s3_user_credential, [non_strict]),
    ok = meck:expect(leo_s3_user_credential, find_by_access_key_id,
                     fun(_) ->
                             {ok, #user_credential{}}
                     end),

    SignParams0 = #sign_params{http_verb     = <<"GET">>,
                               content_md5   = <<>>,
                               content_type  = <<>>,
                               date          = <<"Tue, 27 Mar 2007 19:36:42 +0000">>,
                               bucket        = <<"johnsmith">>,
                               raw_uri       = <<"/photos/puppy.jpg">>,
                               requested_uri = <<"/photos/puppy.jpg">>
                              },
    {Signature0, _, _} = leo_s3_auth:get_signature(SecretAccessKey, SignParams0, #sign_v4_params{}),
    Authorization0 = << <<"AWS ">>/binary, AccessKeyId/binary, <<":">>/binary, Signature0/binary >>,

    {ok, AccessKeyId, _} = leo_s3_auth:authenticate(Authorization0, SignParams0, false),
    {ok, Credential}  = leo_s3_auth:get_credential(AccessKeyId),
    ?assertEqual(AccessKeyId,     Credential#credential.access_key_id),
    ?assertEqual(SecretAccessKey, Credential#credential.secret_access_key),

    %% removed a user-credential
    _ = meck:unload(leo_s3_user_credential),
    ok = meck:new(leo_s3_user_credential, [non_strict]),
    ok = meck:expect(leo_s3_user_credential, find_by_access_key_id,
                     fun(_) ->
                             not_found
                     end),
    ?assertEqual(not_found, leo_s3_auth:get_credential(AccessKeyId)),


    %% inspect-4 - for authentication
    Authorization1 = << <<"AWS ">>/binary, AccessKeyId/binary, <<":example">>/binary >>,
    {error, unmatch} = leo_s3_auth:authenticate(Authorization1, SignParams0, false),

    %% inspect-5 - for authentication
    _ = meck:unload(leo_s3_bucket),
    ok = meck:new(leo_s3_bucket, [non_strict]),
    ok = meck:expect(leo_s3_bucket, head,
                     fun(_AccessKeyId, _Bucket) ->
                             not_found
                     end),
    {error, unmatch} = leo_s3_auth:authenticate(Authorization0, SignParams0, false),

    %% inspect-6 - for authentication
    _ = meck:unload(leo_s3_bucket),
    ok = meck:new(leo_s3_bucket, [non_strict]),
    ok = meck:expect(leo_s3_bucket, head,
                     fun(_AccessKeyId, _Bucket) ->
                             ok
                     end),
    SignParams1 = #sign_params{http_verb     = <<"GET">>,
                               content_md5   = <<>>,
                               content_type  = <<>>,
                               date          = <<"Tue, 27 Mar 2007 19:36:42 +0000">>,
                               bucket        = <<"johnsmith">>,
                               raw_uri       = <<"/">>,
                               requested_uri = <<"/">>
                              },
    {Signature1, _, _} = leo_s3_auth:get_signature(SecretAccessKey, SignParams1, #sign_v4_params{}),
    Authorization2 = << <<"AWS ">>/binary, AccessKeyId/binary, <<":">>/binary, Signature1/binary >>,

    {ok, AccessKeyId, _} = leo_s3_auth:authenticate(Authorization2, SignParams1, false),

    %% check checksum
    {ok, Checksum} = leo_s3_auth:checksum(),
    ?assertEqual(true, Checksum > 0),


    %% check bulk-insert
    {ok, RetL_1} = leo_s3_auth:find_all(),
    ok = leo_s3_auth:bulk_put([#credential{access_key_id = <<"_1_">>},
                               #credential{access_key_id = <<"_2_">>},
                               #credential{access_key_id = <<"_3_">>},
                               #credential{access_key_id = <<"_4_">>},
                               #credential{access_key_id = <<"_5_">>}]),
    {ok, RetL_2} = leo_s3_auth:find_all(),
    ?assertEqual(5, length(RetL_2) - length(RetL_1)),

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


    %% inspect-1
    AccessKeyId     = <<"example_access_key_id">>,
    SecretAccessKey = <<"example_secret_key">>,

    ok = meck:new(leo_s3_user, [non_strict]),
    ok = meck:expect(leo_s3_user, find_by_id,
                     fun(_) ->
                             not_found
                     end),

    ok = meck:new(leo_s3_bucket, [non_strict]),
    ok = meck:expect(leo_s3_bucket, head,
                     fun(_AccessKeyId, _Bucket) ->
                             ok
                     end),

    _  = rpc:call(Manager1, meck, unload, []),
    ok = rpc:call(Manager1, meck, new,    [leo_s3_auth, [no_link, non_strict]]),
    ok = rpc:call(Manager1, meck, expect, [leo_s3_auth, get_credential,
                                           fun(_AccessKeyId) ->
                                                   {ok, #credential{access_key_id     = AccessKeyId,
                                                                    secret_access_key = SecretAccessKey,
                                                                    created_at        = 0}}
                                           end]),

    ok = leo_s3_auth:start(slave, [Manager1]),

    SignParams = #sign_params{http_verb     = <<"GET">>,
                              content_md5   = <<>>,
                              content_type  = <<>>,
                              date          = <<"Tue, 27 Mar 2007 19:36:42 +0000">>,
                              bucket        = <<"johnsmith">>,
                              raw_uri       = <<"/photos/puppy.jpg">>,
                              requested_uri = <<"/photos/puppy.jpg">>
                             },
    {Signature0, _, _} = leo_s3_auth:get_signature(SecretAccessKey, SignParams, #sign_v4_params{}),
    Authorization0 = << <<"AWS ">>/binary, AccessKeyId/binary, <<":">>/binary, Signature0/binary >>,
    Authorization1 = << <<"AWS ">>/binary, AccessKeyId/binary, <<":EXAMPLE">>/binary >>,

    {ok, AccessKeyId, _} = leo_s3_auth:authenticate(Authorization0, SignParams, false),
    {error,unmatch} = leo_s3_auth:authenticate(Authorization1, SignParams, false),

    {ok, #credential{access_key_id     = AccessKeyId,
                     secret_access_key = SecretAccessKey
                    }} = leo_s3_libs_data_handler:lookup({ets, leo_s3_credentials}, AccessKeyId),
    1 = leo_s3_libs_data_handler:size({ets, leo_s3_credentials}),

    %% inspect-4 - for authentication
    _  = rpc:call(Manager1, meck, unload, []),
    ok = rpc:call(Manager1, meck, new,    [leo_s3_auth, [no_link, non_strict]]),
    ok = rpc:call(Manager1, meck, expect, [leo_s3_auth, get_credential,
                                           fun(_AccessKeyId) ->
                                                   not_found
                                           end]),
    ets:delete_all_objects(leo_s3_credentials),

    {error,unmatch} = leo_s3_auth:authenticate(Authorization0, SignParams, false),

    %% update_providers
    Manager2 = list_to_atom("manager_2@" ++ Hostname),
    ok = leo_s3_auth:update_providers([Manager2]),

    %% teardown
    slave:stop(Manager1),
    net_kernel:stop(),
    meck:unload(),
    ok.


%% @doc Authentication Header TEST
%% @ref <http://docs.amazonwebservices.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader>
%%
-define(AWSAccessKeyId,     <<"AKIAIOSFODNN7EXAMPLE">>).
-define(AWSSecretAccessKey, <<"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY">>).

%% @doc Object GET
authenticate_0_(_) ->
    %% == PARAMS ==
    %% AWSAccessKeyId:     AKIAIOSFODNN7EXAMPLE
    %% AWSSecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

    %% == REQUEST ==
    %% GET /photos/puppy.jpg HTTP/1.1
    %% Host: johnsmith.s3.amazonaws.com
    %% Date: Tue, 27 Mar 2007 19:36:42 +0000
    %%
    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
    %% bWq2s1WEIj+Ydj0vQ697zp+IXMU=

    %% == StringToSign ==
    %% GET\n
    %% \n
    %% \n
    %% Tue, 27 Mar 2007 19:36:42 +0000\n
    %% /johnsmith/photos/puppy.jpg

    SignParams = #sign_params{http_verb     = <<"GET">>,
                              content_md5   = <<>>,
                              content_type  = <<>>,
                              date          = <<"Tue, 27 Mar 2007 19:36:42 +0000">>,
                              bucket        = <<"johnsmith">>,
                              raw_uri       = <<"/photos/puppy.jpg">>,
                              requested_uri = <<"/photos/puppy.jpg">>
                             },

    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, #sign_v4_params{}),
    ?assertEqual(<<"bWq2s1WEIj+Ydj0vQ697zp+IXMU=">>, Ret),
    ok.


%% @doc Object PUT
authenticate_1_(_) ->
    %% == PARAMS ==
    %% PUT /photos/puppy.jpg HTTP/1.1
    %% Content-Type: image/jpeg
    %% Content-Length: 94328
    %% Host: johnsmith.s3.amazonaws.com
    %% Date: Tue, 27 Mar 2007 21:15:45 +0000
    %%
    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
    %% MyyxeRY7whkBe+bq8fHCL/2kKUg=

    %% == StringToSign ==
    %% PUT\n
    %% \n
    %% image/jpeg\n
    %% Tue, 27 Mar 2007 21:15:45 +0000\n
    %% /johnsmith/photos/puppy.jpg

    SignParams = #sign_params{http_verb     = <<"PUT">>,
                              content_md5   = <<>>,
                              content_type  = <<"image/jpeg">>,
                              date          = <<"Tue, 27 Mar 2007 21:15:45 +0000">>,
                              bucket        = <<"johnsmith">>,
                              raw_uri       = <<"/photos/puppy.jpg">>,
                              requested_uri = <<"/photos/puppy.jpg">>
                             },

    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, #sign_v4_params{}),
    ?assertEqual(<<"MyyxeRY7whkBe+bq8fHCL/2kKUg=">>, Ret),
    ok.


%% @doc List
authenticate_2_(_) ->
    %% == PARAMS ==
    %% GET /?prefix=photos&max-keys=50&marker=puppy HTTP/1.1
    %% User-Agent: Mozilla/5.0
    %% Host: johnsmith.s3.amazonaws.com
    %% Date: Tue, 27 Mar 2007 19:42:41 +0000
    %%
    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
    %% htDYFYduRNen8P9ZfE/s9SuKy0U=

    %% == StringToSign ==
    %% GET\n
    %% \n
    %% \n
    %% Tue, 27 Mar 2007 19:42:41 +0000\n
    %% /johnsmith/

    SignParams = #sign_params{http_verb     = <<"GET">>,
                              content_md5   = <<>>,
                              content_type  = <<>>,
                              date          = <<"Tue, 27 Mar 2007 19:42:41 +0000">>,
                              bucket        = <<"johnsmith">>,
                              raw_uri       = <<"/">>,
                              requested_uri = <<"/">>,
                              query_str     = <<"?prefix=photos&max-keys=50&marker=puppy">>
                             },
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, #sign_v4_params{}),
    ?assertEqual(<<"htDYFYduRNen8P9ZfE/s9SuKy0U=">>, Ret),
    ok.


%% @doc Fetch
authenticate_3_(_) ->
    %% == PARAMS ==
    %% GET /?acl HTTP/1.1
    %% Host: johnsmith.s3.amazonaws.com
    %%         Date: Tue, 27 Mar 2007 19:44:46 +0000
    %%
    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
    %% c2WLPFtWHVgbEmeEG93a4cG37dM=

    %% == StringToSign ==
    %% GET\n
    %% \n
    %% \n
    %% Tue, 27 Mar 2007 19:44:46 +0000\n
    %% /johnsmith/?acl

    SignParams = #sign_params{http_verb     = <<"GET">>,
                              content_md5   = <<>>,
                              content_type  = <<>>,
                              date          = <<"Tue, 27 Mar 2007 19:44:46 +0000">>,
                              bucket        = <<"johnsmith">>,
                              raw_uri       = <<"/">>,
                              requested_uri = <<"/">>,
                              query_str     = <<"?acl">>
                             },
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, #sign_v4_params{}),
    ?assertEqual(<<"c2WLPFtWHVgbEmeEG93a4cG37dM=">>, Ret),
    ok.


%% @doc Delete
authenticate_4_(_) ->
    %% NOTE: In this case the field for the actual 'Date' header is left blank in the StringToSign.

    %% == PARAMS ==
    %% DELETE /johnsmith/photos/puppy.jpg HTTP/1.1
    %% User-Agent: dotnet
    %% Host: s3.amazonaws.com
    %% Date: Tue, 27 Mar 2007 21:20:27 +0000
    %%
    %% x-amz-date: Tue, 27 Mar 2007 21:20:26 +0000
    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:9b2sXq0KfxsxHtdZkzx/9Ngqyh8=

    %% == StringToSign ==
    %% DELETE\n
    %% \n
    %% \n
    %% x-amz-date:Tue, 27 Mar 2007 21:20:26 +0000\n
    %% /johnsmith/photos/puppy.jpg

    SignParams = #sign_params{http_verb     = <<"DELETE">>,
                              content_md5   = <<>>,
                              content_type  = <<>>,
                              date          = <<"Tue, 27 Mar 2007 21:20:27 +0000">>,
                              bucket        = <<"johnsmith">>,
                              raw_uri       = <<"/photos/puppy.jpg">>,
                              requested_uri = <<"/photos/puppy.jpg">>,
                              amz_headers   = [
                                              {"x-amz-date", "Tue, 27 Mar 2007 21:20:26 +0000"}]
                             },
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, #sign_v4_params{}),
    ?assertEqual(<<"R4dJ53KECjStyBO5iTBJZ4XVOaI=">>, Ret),
    %% ?assertEqual(<<"9b2sXq0KfxsxHtdZkzx/9Ngqyh8=">>, Ret),
    ok.


%% @doc Upload
authenticate_5_(_) ->
    %% == PARAMS ==
    %% PUT /db-backup.dat.gz HTTP/1.1
    %% User-Agent: curl/7.15.5
    %% Host: static.johnsmith.net:8080
    %% Date: Tue, 27 Mar 2007 21:06:08 +0000
    %%
    %% x-amz-acl: public-read
    %% content-type: application/x-download
    %% Content-MD5: 4gJE4saaMU4BqNR0kLY+lw==
    %% X-Amz-Meta-ReviewedBy: joe@johnsmith.net
    %% X-Amz-Meta-ReviewedBy: jane@johnsmith.net
    %% X-Amz-Meta-FileChecksum: 0x02661779
    %% X-Amz-Meta-ChecksumAlgorithm: crc32
    %% Content-Disposition: attachment; filename=database.dat
    %% Content-Encoding: gzip
    %% Content-Length: 5913339
    %%
    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
    %% ilyl83RwaSoYIEdixDQcA4OnAnc=

    %% == StringToSign ==
    %% PUT\n
    %% 4gJE4saaMU4BqNR0kLY+lw==\n
    %% application/x-download\n
    %% Tue, 27 Mar 2007 21:06:08 +0000\n
    %%
    %% x-amz-acl:public-read\n
    %% x-amz-meta-checksumalgorithm:crc32\n
    %% x-amz-meta-filechecksum:0x02661779\n
    %% x-amz-meta-reviewedby:joe@johnsmith.net,jane@johnsmith.net\n
    %% /static.johnsmith.net/db-backup.dat.gz

    SignParams1 = #sign_params{http_verb     = <<"PUT">>,
                               content_md5   = <<"4gJE4saaMU4BqNR0kLY+lw==">>,
                               content_type  = <<"application/x-download">>,
                               date          = <<"Tue, 27 Mar 2007 21:06:08 +0000">>,
                               bucket        = <<"static.johnsmith.net">>,
                               raw_uri       = <<"/db-backup.dat.gz">>,
                               requested_uri = <<"/db-backup.dat.gz">>,
                               amz_headers   = [{"x-amz-Acl", "public-read"},
                                                {"x-amz-Meta-ReviewedBy", "joe@johnsmith.net"},
                                                {"x-amz-Meta-ReviewedBy", "jane@johnsmith.net"},
                                                {"x-amz-Meta-FileChecksum","0x02661779"},
                                                {"x-amz-Meta-ChecksumAlgorithm", "crc32"}]},
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams1, #sign_v4_params{}),
    ?assertEqual(<<"ilyl83RwaSoYIEdixDQcA4OnAnc=">>, Ret),
    ok.


%% @doc List All My Buckets
authenticate_6_(_) ->
    %% == PARAMS ==
    %% GET / HTTP/1.1
    %% Host: s3.amazonaws.com
    %% Date: Wed, 28 Mar 2007 01:29:59 +0000
    %%
    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:qGdzdERIC03wnaRNKh6OqZehG9s=

    %% == StringToSign ==
    %% GET\n
    %% \n
    %% \n
    %% Wed, 28 Mar 2007 01:29:59 +0000\n
    %% /

    SignParams = #sign_params{http_verb     = <<"GET">>,
                              content_md5   = <<>>,
                              content_type  = <<>>,
                              date          = <<"Wed, 28 Mar 2007 01:29:59 +0000">>,
                              bucket        = <<>>,
                              raw_uri       = <<"/">>,
                              requested_uri = <<"/">>,
                              amz_headers   = []},
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, #sign_v4_params{}),
    ?assertEqual(<<"qGdzdERIC03wnaRNKh6OqZehG9s=">>, Ret),
    ok.


%% @doc Unicode Keys
authenticate_7_(_) ->
    %% == PARAMS ==
    %% GET /dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re HTTP/1.1
    %% Host: s3.amazonaws.com
    %% Date: Wed, 28 Mar 2007 01:49:49 +0000
    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:DNEZGsoieTZ92F3bUfSPQcbGmlM=

    %% == StringToSign ==
    %% GET\n
    %% \n
    %% \n
    %% Wed, 28 Mar 2007 01:49:49 +0000\n
    %% /dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re

    SignParams = #sign_params{http_verb     = <<"GET">>,
                              content_md5   = <<>>,
                              content_type  = <<>>,
                              date          = <<"Wed, 28 Mar 2007 01:49:49 +0000">>,
                              bucket        = <<>>,
                              raw_uri       = <<"/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re">>,
                              requested_uri = <<"/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re">>,
                              amz_headers   = []},
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, #sign_v4_params{}),
    ?assertEqual(<<"DNEZGsoieTZ92F3bUfSPQcbGmlM=">>, Ret),
    ok.

%% @doc Get an object with versionid
authenticate_8_(_) ->
    %% == PARAMS ==
    %% GET /path/to/file?versionid=9 HTTP/1.1
    %% User-Agent: Mozilla/5.0
    %% Host: johnsmith.s3.amazonaws.com
    %% Date: Tue, 27 Mar 2007 19:42:41 +0000
    %%
    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
    %% htDYFYduRNen8P9ZfE/s9SuKy0U=

    %% == StringToSign ==
    %% GET\n
    %% \n
    %% \n
    %% Tue, 27 Mar 2007 19:42:41 +0000\n
    %% /johnsmith/path/to/file?versionid=9

    SignParams = #sign_params{http_verb     = <<"GET">>,
                              content_md5   = <<>>,
                              content_type  = <<>>,
                              date          = <<"Tue, 27 Mar 2007 19:42:41 +0000">>,
                              bucket        = <<"johnsmith">>,
                              raw_uri       = <<"/path/to/file">>,
                              requested_uri = <<"/path/to/file">>,
                              query_str     = <<"?versionid=9">>
                             },
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, #sign_v4_params{}),
    ?assertEqual(<<"ld6nhMmeUif8N/zae7DGfB5xYiI=">>, Ret),
    ok.

%% @doc Get an object ACL with versionid
authenticate_9_(_) ->
    %% == PARAMS ==
    %% GET /path/to/file?versionid=9&acl HTTP/1.1
    %% User-Agent: Mozilla/5.0
    %% Host: johnsmith.s3.amazonaws.com
    %% Date: Tue, 27 Mar 2007 19:42:41 +0000
    %%
    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
    %% htDYFYduRNen8P9ZfE/s9SuKy0U=

    %% == StringToSign ==
    %% GET\n
    %% \n
    %% \n
    %% Tue, 27 Mar 2007 19:42:41 +0000\n
    %% /johnsmith/path/to/file?acl&versionid=9

    %% query params must be sorted lexicographically by param name
    %% so in this example, acl must be appeared at first
    SignParams = #sign_params{http_verb     = <<"GET">>,
                              content_md5   = <<>>,
                              content_type  = <<>>,
                              date          = <<"Tue, 27 Mar 2007 19:42:41 +0000">>,
                              bucket        = <<"johnsmith">>,
                              raw_uri       = <<"/path/to/file">>,
                              requested_uri = <<"/path/to/file">>,
                              query_str     = <<"?acl&versionid=9">>
                             },
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, #sign_v4_params{}),
    ?assertEqual(<<"b3zx5W2PwpsnI/raaZH7heh1NH0=">>, Ret),
    ok.

%% @doc Get an object with parameters overriding the response header values
authenticate_10_(_) ->
    %% == PARAMS ==
    %% GET /path/to/file?response-cache-control=No-cache&response-content-disposition=attachment%3B%20filename%3Dtesting.txt&response-content-encoding=x-gzip&response-content-language=mi%2C%20en&response-expires=Thu%2C%2001%20Dec%201994%2016:00:00%20GMT
    %% User-Agent: Mozilla/5.0
    %% Host: johnsmith.s3.amazonaws.com
    %% Date: Tue, 27 Mar 2007 19:42:41 +0000
    %%
    %% Authorization: AWS AKIAIOSFODNN7EXAMPLE:
    %% htDYFYduRNen8P9ZfE/s9SuKy0U=

    %% == StringToSign ==
    %% GET\n
    %% \n
    %% \n
    %% Tue, 27 Mar 2007 19:42:41 +0000\n
    %% /johnsmith/path/to/file?response-cache-control=No-cache&response-content-disposition=attachment; filename=testing.txt&response-content-encoding=x-gzip&response-content-language=mi, en&response-expires=Thu, 01 Dec 1994 16:00:00 GMT

    %% query params must be sorted lexicographically by param name
    %% so in this example, acl must be appeared at first
    %% AND query params must be URL decoded when signing
    SignParams = #sign_params{http_verb     = <<"GET">>,
                              content_md5   = <<>>,
                              content_type  = <<>>,
                              date          = <<"Tue, 27 Mar 2007 19:42:41 +0000">>,
                              bucket        = <<"johnsmith">>,
                              raw_uri       = <<"/path/to/file">>,
                              requested_uri = <<"/path/to/file">>,
                              query_str     = <<"?response-cache-control=No-cache&response-content-disposition=attachment%3B%20filename%3Dtesting.txt&response-content-encoding=x-gzip&response-content-language=mi%2C%20en&response-expires=Thu%2C%2001%20Dec%201994%2016:00:00%20GMT">>
                             },
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, #sign_v4_params{}),
    ?assertEqual(<<"IjeV85YN0SCCw26yHd8DXCIvBjk=">>, Ret),
    ok.

-define(AWSSecretAccessKeyV4, <<"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY">>).
authenticate_v4_1(_) ->
    %% == PARAMS ==
    %% POST https://iam.amazonaws.com/ HTTP/1.1
    %% host: iam.amazonaws.com
    %% Content-type: application/x-www-form-urlencoded; charset=utf-8
    %% x-amz-date: 20110909T233600Z
    %%
    %% Action=ListUsers&Version=2010-05-08

    %% == Canonical Request ==
    %% POST
    %% /
    %%
    %% content-type:application/x-www-form-urlencoded; charset=utf-8
    %% host:iam.amazonaws.com
    %% x-amz-date:20110909T233600Z
    %%
    %% content-type;host;x-amz-date
    %% b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2

    %% == StringToSign ==
    %% AWS4-HMAC-SHA256
    %% 20110909T233600Z
    %% 20110909/us-east-1/iam/aws4_request
    %% 3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2

    %% == Signing Key ==
    %% <<152,241,216,137,254,196,244,66,26,220,82,43,171,12,225,248,46,105,41,194,98,237,21,229,169,76,144,239,209,227,176,231>>

    Headers     = [{<<"content-type">>, <<"application/x-www-form-urlencoded; charset=utf-8">>},
                   {<<"host">>, <<"iam.amazonaws.com">>},
                   {<<"x-amz-date">>, <<"20110909T233600Z">>},
                   {<<"x-amz-content-sha256">>, <<"b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2">>}
                  ],
    QueryStr    = <<>>,
    SignParams  = #sign_params{http_verb     = <<"POST">>,
                               date          = <<>>,
                               raw_uri       = <<"/">>,
                               headers       = Headers,
                               sign_ver      = v4,
                               query_str     = QueryStr
                              },
    SignV4Params = #sign_v4_params{credential       = <<"AKIAIOSFODNN7EXAMPLE/20110909/us-east-1/iam/aws4_request">>,
                                   signed_headers   = <<"content-type;host;x-amz-date">>
                                  },
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKeyV4, SignParams, SignV4Params),
    ?assertEqual(<<"ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c">>, Ret),
    ok.

authenticate_v4_2(_) ->
    ok = leo_s3_auth:start(master, []),
    ok = leo_s3_auth:create_table(ram_copies, [node()]),

    {ok, Keys} = leo_s3_auth:create_key(?USER_ID),
    AccessKeyId     = proplists:get_value(access_key_id,     Keys),
    SecretAccessKey = proplists:get_value(secret_access_key, Keys),

    Headers     = [{<<"content-type">>, <<"application/x-www-form-urlencoded; charset=utf-8">>},
                   {<<"host">>, <<"iam.amazonaws.com">>},
                   {<<"x-amz-date">>, <<"20110909T233600Z">>},
                   {<<"x-amz-content-sha256">>, <<"b6359072c78d70ebee1e81adcbab4f01bf2c23245fa365ef83fe8f1f955085e2">>}
                  ],
    QueryStr    = <<>>,
    SignParams  = #sign_params{http_verb     = <<"POST">>,
                               date          = <<>>,
                               raw_uri       = <<"/">>,
                               headers       = Headers,
                               sign_ver      = v4,
                               query_str     = QueryStr
                              },
    Credential  = <<AccessKeyId/binary, "/20110909/us-east-1/iam/aws4_request">>,
    SignedHeaders = <<"content-type;host;x-amz-date">>,
    SignV4Params = #sign_v4_params{credential       = <<AccessKeyId/binary, "/20110909/us-east-1/iam/aws4_request">>,
                                   signed_headers   = <<"content-type;host;x-amz-date">>
                                  },
    {Signature, _, _} = leo_s3_auth:get_signature(SecretAccessKey, SignParams, SignV4Params),
    Authorization = <<"AWS4-HMAC-SHA256 ",
                      "Credential=", Credential/binary, ", ", 
                      "SignedHeaders=", SignedHeaders/binary, ", ",
                      "Signature=", Signature/binary>>,
    {ok, AccessKeyId, _} = leo_s3_auth:authenticate(Authorization, SignParams, false),
    ok.

%% @doc Authorization Header TEST (Signature V4)
%% @ref <http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html>

%% @doc GET Object
authenticate_v4_3(_) ->
    %% == PARAMS ==
    %% GET /test.txt HTTP/1.1
    %% Host: examplebucket.s3.amazonaws.com
    %% Date: Fri, 24 May 2013 00:00:00 GMT
    %% Authorization: SignatureToBeCalculated
    %% Range: bytes=0-9 
    %% x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    %% x-amz-date: 20130524T000000Z 

    %% == Canonical Request ==
    %% GET
    %% /test.txt
    %%
    %% host:examplebucket.s3.amazonaws.com
    %% range:bytes=0-9
    %% x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    %% x-amz-date:20130524T000000Z
    %%
    %% host;range;x-amz-content-sha256;x-amz-date
    %% e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  

    %% == StringToSign ==
    %% AWS4-HMAC-SHA256
    %% 20130524T000000Z
    %% 20130524/us-east-1/s3/aws4_request
    %% 7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972

    Headers     = [
                   {<<"host">>, <<"examplebucket.s3.amazonaws.com">>},
                   {<<"range">>, <<"bytes=0-9">>},
                   {<<"x-amz-date">>, <<"20130524T000000Z">>},
                   {<<"x-amz-content-sha256">>, <<"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">>}
                  ],
    QueryStr    = <<>>,
    SignParams  = #sign_params{http_verb     = <<"GET">>,
                               date          = <<>>,
                               raw_uri       = <<"/test.txt">>,
                               headers       = Headers,
                               sign_ver      = v4,
                               query_str     = QueryStr
                              },
    SignV4Params = #sign_v4_params{credential       = <<?AWSAccessKeyId/binary, "/20130524/us-east-1/s3/aws4_request">>,
                                   signed_headers   = <<"host;range;x-amz-content-sha256;x-amz-date">>
                                  },
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, SignV4Params),
    ?assertEqual(<<"f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41">>, Ret),
    ok.

%% @doc PUT Object
authenticate_v4_4(_) ->
    %% == PARAMS ==
    %% PUT test$file.txt HTTP/1.1
    %% Host: examplebucket.s3.amazonaws.com
    %% Date: Fri, 24 May 2013 00:00:00 GMT
    %%
    %% Authorization: SignatureToBeCalculated
    %% x-amz-date: 20130524T000000Z 
    %% x-amz-storage-class: REDUCED_REDUNDANCY
    %% x-amz-content-sha256: 44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072
    %%
    %% <Payload>

    %% == Canonical Request ==
    %% PUT
    %% /test%24file.text
    %%
    %% date:Fri, 24 May 2013 00:00:00 GMT
    %% host:examplebucket.s3.amazonaws.com
    %% x-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072
    %% x-amz-date:20130524T000000Z
    %% x-amz-storage-class:REDUCED_REDUNDANCY
    %%
    %% date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class
    %% 44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072

    %% == StringToSign ==
    %% AWS4-HMAC-SHA256
    %% 20130524T000000Z
    %% 20130524/us-east-1/s3/aws4_request
    %% 9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d

    Headers     = [
                   {<<"date">>, <<"Fri, 24 May 2013 00:00:00 GMT">>},
                   {<<"host">>, <<"examplebucket.s3.amazonaws.com">>},
                   {<<"x-amz-content-sha256">>, <<"44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072">>},
                   {<<"x-amz-date">>, <<"20130524T000000Z">>},
                   {<<"x-amz-storage-class">>, <<"REDUCED_REDUNDANCY">>}
                  ],
    QueryStr    = <<>>,
    SignParams  = #sign_params{http_verb     = <<"PUT">>,
                               date          = <<"Fri, 24 May 2013 00:00:00 GMT">>,
                               raw_uri       = <<"/test%24file.text">>,
                               headers       = Headers,
                               sign_ver      = v4,
                               query_str     = QueryStr
                              },
    SignV4Params = #sign_v4_params{credential       = <<?AWSAccessKeyId/binary, "/20130524/us-east-1/s3/aws4_request">>,
                                   signed_headers   = <<"date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class">>
                                  },
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, SignV4Params),
    ?assertEqual(<<"98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd">>, Ret),
    ok.

%% @doc GET Bucket Lifecycle
authenticate_v4_5(_) ->
    %% == PARAMS ==
    %% GET ?lifecycle HTTP/1.1
    %% Host: examplebucket.s3.amazonaws.com
    %% Authorization: SignatureToBeCalculated
    %% x-amz-date: 20130524T000000Z 
    %% x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

    %% == Canonical Request ==
    %% GET
    %% /
    %% lifecycle=
    %% host:examplebucket.s3.amazonaws.com
    %% x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    %% x-amz-date:20130524T000000Z
    %%
    %% host;x-amz-content-sha256;x-amz-date
    %% e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

    %% == StringToSign ==
    %% AWS4-HMAC-SHA256
    %% 20130524T000000Z
    %% 20130524/us-east-1/s3/aws4_request
    %% 9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca

    Headers     = [
                   {<<"host">>, <<"examplebucket.s3.amazonaws.com">>},
                   {<<"x-amz-date">>, <<"20130524T000000Z">>},
                   {<<"x-amz-content-sha256">>, <<"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">>}
                  ],
    QueryStr    = <<"lifecycle=">>,
    SignParams  = #sign_params{http_verb     = <<"GET">>,
                               date          = <<>>,
                               raw_uri       = <<"/">>,
                               headers       = Headers,
                               sign_ver      = v4,
                               query_str     = QueryStr
                              },
    SignV4Params = #sign_v4_params{credential       = <<?AWSAccessKeyId/binary, "/20130524/us-east-1/s3/aws4_request">>,
                                   signed_headers   = <<"host;x-amz-content-sha256;x-amz-date">>
                                  },
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, SignV4Params),
    ?assertEqual(<<"fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543">>, Ret),
    ok.

%% @doc Get Bucket (List Objects)
authenticate_v4_6(_) ->
    %% == PARAMS ==
    %% GET ?max-keys=2&prefix=J HTTP/1.1
    %% Host: examplebucket.s3.amazonaws.com
    %% Authorization: SignatureToBeCalculated
    %% x-amz-date: 20130524T000000Z 
    %% x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

    %% == Canonical Request ==
    %% GET
    %% /
    %% max-keys=2&prefix=J
    %% host:examplebucket.s3.amazonaws.com
    %% x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    %% x-amz-date:20130524T000000Z
    %%
    %% host;x-amz-content-sha256;x-amz-date
    %% e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

    %% == StringToSign ==
    %% AWS4-HMAC-SHA256
    %% 20130524T000000Z
    %% 20130524/us-east-1/s3/aws4_request
    %% df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7

    Headers     = [
                   {<<"host">>, <<"examplebucket.s3.amazonaws.com">>},
                   {<<"x-amz-date">>, <<"20130524T000000Z">>},
                   {<<"x-amz-content-sha256">>, <<"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">>}
                  ],
    QueryStr    = <<"max-keys=2&prefix=J">>,
    SignParams  = #sign_params{http_verb     = <<"GET">>,
                               date          = <<>>,
                               raw_uri       = <<"/">>,
                               headers       = Headers,
                               sign_ver      = v4,
                               query_str     = QueryStr
                              },
    SignV4Params = #sign_v4_params{credential       = <<?AWSAccessKeyId/binary, "/20130524/us-east-1/s3/aws4_request">>,
                                   signed_headers   = <<"host;x-amz-content-sha256;x-amz-date">>
                                  },
    {Ret, _, _} = leo_s3_auth:get_signature(?AWSSecretAccessKey, SignParams, SignV4Params),
    ?assertEqual(<<"34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7">>, Ret),
    ok.

-endif.
