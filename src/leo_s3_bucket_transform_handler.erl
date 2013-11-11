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
%% Leo S3 Libs - Bucket Transform Handler
%% @doc
%% @end
%%======================================================================
-module(leo_s3_bucket_transform_handler).

-author('Yosuke Hara').
-author('Yoshiyuki Kanno').

-include("leo_s3_libs.hrl").
-include("leo_s3_bucket.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([transform/0]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------
%% @doc The table schema migrate to the new one by using mnesia:transform_table
%%
-spec(transform() -> ok).
transform() ->
    case mnesia:table_info(?BUCKET_TABLE, record_name) of
        %% Stored bucket-record is 'bucket' which is old version
        %% Then transform records to current-version
        bucket ->
            {atomic, ok} = mnesia:transform_table(
                             ?BUCKET_TABLE,
                             fun transform/1, record_info(fields, ?BUCKET), ?BUCKET),
            ok;
        _ ->
            ok
    end.

%% @private
transform(#?BUCKET{} = Bucket) ->
    Bucket;
transform(#bucket{name       = Name,
                  access_key = AccessKey,
                  created_at = CreatedAt}) ->
    #bucket_0_16_0{name                = Name,
                   access_key          = AccessKey,
                   acls                = [],
                   last_synchroized_at = 0,
                   created_at          = CreatedAt,
                   last_modified_at    = 0}.

