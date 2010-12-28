%% Copyright (c) 2010, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%%
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%%
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%%
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(herp).
-behaviour(gen_server).

-define(SERVER, ?MODULE).

-include("pkt.hrl").

-export([start/0, start/1, stop/0, bridge/2]).
-export([start_link/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
        terminate/2, code_change/3]).

-record(state, {
        s,              % PF_PACKET socket
        i,              % IF Index
        gw,             % Gateway MAC address
        ip,             % our IP address
        mac             % our MAC address
    }).


%%--------------------------------------------------------------------
%%% Exports
%%--------------------------------------------------------------------
start() ->
    [Dev] = packet:default_interface(),
    start(Dev).
start(Dev) ->
    start_link(Dev).

stop() ->
    gen_server:call(?MODULE, stop).

start_link(Dev) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Dev], []).

bridge(MAC, Packet) when is_binary(Packet) ->
    gen_server:call(?MODULE, {packet, MAC, Packet}).


%%--------------------------------------------------------------------
%%% Callbacks
%%--------------------------------------------------------------------
init([Dev]) ->
    {ok, PL} = inet:ifget(Dev, [addr, hwaddr]),

    {ok, {M1,M2,M3,M4,M5,M6}, _} = packet:gateway(Dev),

    IP = proplists:get_value(addr, PL),
    MAC = list_to_binary(proplists:get_value(hwaddr, PL)),

    {ok, Socket} = packet:socket(?ETH_P_IP),
    Ifindex = packet:ifindex(Socket, Dev),     

    State = #state{
        s = Socket,
        i = Ifindex,
        ip = IP,
        mac = MAC,
        gw = <<M1,M2,M3,M4,M5,M6>>
    },

    spawn_link(fun() -> sniff(Socket, State) end),

    {ok, State}.

handle_call({packet, DstMAC, Packet}, _From, #state{
        mac = MAC,
        s = Socket,
        i = Ifindex} = State) ->

    Ether = pkt:ether(#ether{
            dhost = DstMAC,
            shost = MAC,
            type = ?ETH_P_IP
        }),

    error_logger:info_report([{src, machex(MAC)}, {dst, machex(DstMAC)}]),
    packet:send(Socket, Ifindex, <<Ether/binary, Packet/binary>>),
    {reply, ok, State};

handle_call(stop, _From, State) ->
    {stop, shutdown, ok, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

% WTF?
handle_info(Info, State) ->
    error_logger:error_report([wtf, Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%--------------------------------------------------------------------
%%% Read ARP packets from the network and send them to the
%%% gen_server
%%--------------------------------------------------------------------
sniff(Socket, State) ->
    case procket:recvfrom(Socket, 65535) of
        {error, eagain} ->
            timer:sleep(10),
            sniff(Socket, State);
        {ok, Data} ->
            {#ether{} = Ether, Packet} = pkt:ether(Data),
            filter(Ether, Packet, State),
            sniff(Socket, State);
        Error ->
            error_logger:error_report(Error)
    end.

filter(#ether{shost = MAC}, _, #state{mac = MAC}) ->
    ok;
filter(#ether{type = ?ETH_P_IP}, Packet, State) ->
    {#ipv4{daddr = DA}, _} = pkt:ipv4(Packet),
    filter1(DA, Packet, State);
filter(_, _, _) ->
    ok.

filter1(IP, _, #state{ip = IP}) ->
    ok;
filter1(IP, Packet, #state{gw = GW}) ->
    MAC = case packet:arplookup(IP) of
        false -> GW;
        {M1,M2,M3,M4,M5,M6} -> <<M1,M2,M3,M4,M5,M6>>
    end,
    bridge(MAC, Packet).


%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
machex(MAC) when is_binary(MAC) ->
    lists:flatten(string:join([ io_lib:format("~.16B", [N]) || <<N>> <= MAC ], ":")).

