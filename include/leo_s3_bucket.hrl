%%======================================================================
%%
%% Leo Bucket
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
%% Leo Bucket
%% @doc
%% @end
%%======================================================================
-type permission()  :: read|write|read_acp|write_acp|full_control.
-type permissions() :: [permission()].

-record(bucket_acl_info, {
          user_id       :: string(),      %% correspond with user table's user_id
          permissions   :: permissions()  %% permissions
         }).

-type acls() :: [#bucket_acl_info{}].

-record(bucket, {
          name          :: string(), %% bucket name
          access_key    :: string(), %% access key
          acls          :: acls(),   %% acl list
          created_at =0 :: integer() %% create date and time
         }).

-record(bucket_info, {
          type          :: atom(), %% [master | slave]
          db            :: atom(), %% db-type:[ets | mnesia]
          provider = [] :: list()  %% auth-info provides
         }).
