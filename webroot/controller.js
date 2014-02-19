/*
# Copyright (c) 2014 The MITRE Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
*/


$(function() {

    // VARIABLES
    var DEBUG_ENABLED = 0;
    var console_socket = null;
    var data_socket = null;
    var console = document.getElementById('console_box');
    var $command_box = $("#console_cmd") 
    var zen_window = null;
    var zen_window_parent = null;

    //AJAX/Style
    $( "#console" ).dialog({
        autoOpen: true,
        height: 400,
        width: 600
    });

    $("#data_window").tabs({
        activate: function (event, ui) {
            var id = $(this).tabs('option', 'active');
            $("#data_window_list li:eq(" + id + ")").removeClass('unread');
        }
    });

    $(".ui-dialog-titlebar").css({
                    'border': 'none',
                    'height': '18px'
    });


    $("#control_button").button()

    $('.button').button().css({ 
                'width': '90px', 
                'padding-top': '2px', 
                'padding-bottom': '2px' 
    });


    $("#control_button").delegate('', 'click',  function () {
        $("#console").dialog("open")
    });

    $(document).delegate('.delete', 'click', function (){
       closeTab($(this)); 
    });

    $("#console_cmd").keyup(function(event){
        if(event.keyCode == 13){//Enter key
            $("#console_send").click();
        }
    });


    $("#console").keyup(function(event){
        if(event.keyCode == 90){
            event.stopPropagation();
        }

    });


    $(document).keyup(function(event){
        if(event.keyCode == 90){//z

            if (zen_window != null){
                zen_window.removeClass('zen').addClass('ui-corner-bottom')
                    .addClass('ui-widget-content').addClass('ui-tabs-panel');
                zen_window_parent.append(zen_window);

                zen_window = null;
                zen_window_parent = null;
            }else{
                var id = $("#data_window").tabs('option','active');
                var $active_window = $("#data_window_list li:eq(" + id + ")"); 

                if ($active_window.length > 0) {
                    win_id = $active_window.attr('window_id');
                    zen_window = $("#data_window_" + win_id);
                    zen_window_parent = zen_window.parent();
                    $("body").append(zen_window.addClass('zen')
                        .removeClass('ui-tabs-panel')
                        .removeClass('ui-widget-content')
                        .removeClass('ui-corner-bottom'));
                }
            }
        }
    });

    $("#console_send").delegate('', 'click', function (){
        send();
    });

    $("#console_reconnect").delegate('', 'click',function (){
        reconnect();
    });


    if (DEBUG_ENABLED){
        addTab('test','99');
    }


    //Initialization
    if ('MozWebSocket' in window) {
        addToConsole("Using 'MozWebSocket'");
    } else if (!('WebSocket' in window)) {//Can't find standard websocket
        addToConsole('WebSockets do not seem to be supported?');
        return;
    }


    //Auto connect the shell and data sockets
    connect_shell();
    connect_data();

    
    //Functions
    function parseJSONMessage(omessage){
        message = $.parseJSON(omessage);

        if (message.type == 'ctrl'){
            debug_out(message.data.msg);
            if (message.data.msg == 'addmod'){
                addTab(message.data.name, message.data.id);
            }else if (message.data.msg == 'finished' && message.data.status == 'error'){
               addToConsole(message.data.errors);
            }
        }else if(message.type == 'text'){
            output = message.data.data;
            if (!message.data.suppress){
                output += "\n";
            }
            addToDataWindow(output, message.id);
        }
    }

    function addToDataWindow(data, id){
        $("#data_window_" + id).find(".data").children('pre').append(data);

        //Scroll to the bottom
        var $data_span = $("#data_window_" + id).children('.data')
        $data_span.scrollTop($data_span[0].scrollHeight);


        //Highlight inactive tabs with new data
        var $index = $("ul li.ui-state-active").index();
        var $active = $("#data_window_list li:eq("+ $index + ")");
        var $element = $("#element_" + id);
        if ($active.attr('window_id') != $element.attr('window_id')){ 
           //This window is not active
           $element.addClass('unread'); 
        }
        
    }

    function debug_out(message){
        if (DEBUG_ENABLED){
            addToConsole(message);
        }
    }

    function addToConsole(message) {
        //Figure out how to jquery-ize this considering the escaping
        console.value += message + '\n'
        console.scrollTop = console.scrollHeight;
    }

    function send() {
        if ($command_box.val() == 'connect'){
            reconnect()
        }else{
            if (!console_socket) {
                addToConsole('Not connected');
                return;
            }

        console_socket.send($command_box.val());
        }

        addToConsole('# ' + $command_box.val());
        $command_box.val('');
    }

    function connect_ws(address){
        var web_socket = null;

        if ('WebSocket' in window) {
            web_socket = new WebSocket(address);
        } else if ('MozWebSocket' in window) {
            web_socket = new MozWebSocket(address);
        } else {
            return null;
        }

        return web_socket;
    }

    function connect_shell() {
        var address = "ws://"  + window.location.host + "/shell"
        console_socket = connect_ws(address)

        if (console_socket == null){
            addToConsole('Unable to obtain websocket');
            return;
        }

        console_socket.onopen = function () {
            debug_out('Console Connected');
        };

        console_socket.onmessage = function (event) {
            addToConsole(event.data);
        };

        console_socket.onerror = function () {
            addToConsole('Console Connection Error');
        };

        console_socket.onclose = function (event) {
            addToConsole('Console Connection Closed');
            console_socket = null;
        };

    }

    function connect_data() {
        var address =  "ws://" + window.location.host + "/data"
        data_socket = connect_ws(address)

        if (data_socket == null){
            addToConsole('Unable to obtain data websocket');
            return;
        }

        data_socket.onopen = function () {
            debug_out('Data Connected');
        };

        data_socket.onmessage = function (event) {
            parseJSONMessage(event.data);
        };

        data_socket.onerror = function () {
            addToConsole('Data Connection Error\n');
        };

        data_socket.onclose = function (event) {
            addToConsole('Data Connection Closed');
            data_socket = null;
        };
    }



    function reconnect(){
        if(console_socket != null){
            console_socket.close();
            console_socket = null;
        }

        if(data_socket != null){
            data_socket.close();
            data_socket = null;
        }

        connect_shell();
        connect_data();

    }

    function addTab(name, id){

        if ($("#data_window_" + id).length > 0){ //already exists
            return;
        }

        //Append the list element
        $("#data_window_list").append(
                "<li window_id=" + id + 
                " id = 'element_" + id + 
                "'><a href='#data_window_" + 
                id + "'>" + name + 
                "</a><a href='#' class='delete'> <span class= 'ui-icon ui-icon-close' /></a></li>"
        );

        //Append the div with textarea child
        $("#data_window").append(
                "<div id='data_window_" + id + 
                "' class = 'data_container'>" + 
                "<span class = 'data'><pre></pre> </span></div>"
                //"<textarea class = 'data' readonly>" + 
                //"</textarea></div>"
        );

        //Refresh the tabs
        $("#data_window").tabs("refresh");
        $("#data_window").tabs("option","active", $("#data_window_list").children().length - 1);
    };

    function closeTab($tab){
        var window_id = $tab.closest('li').attr('window_id');
        $("#element_" + window_id).remove();
        $("#data_window_" + window_id).remove();   
        $("#data_window").tabs("refresh");
    };

});
