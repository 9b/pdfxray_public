$(document).ready(function() {
    $('html').ajaxSend(function(event, xhr, settings) {
    function getCookie(name) {
        var cookieValue = null;
        if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
            cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
            break;
            }
        }
        }
        return cookieValue;
    }
    if (!(/^http:.*/.test(settings.url) || /^https:.*/.test(settings.url))) {
        // Only send the token to relative URLs i.e. locally.
        xhr.setRequestHeader("X-CSRFToken", getCookie('csrftoken'));
    }
    });

    var hash = $("#drop_storage").attr("name");
	function update_status() {
    $.ajax({
        url: '/file_status/',
        type: 'post',
        dataType: 'json',
        data: { hash: hash },
        success: function(data) {
            if(data.success == true) {
				$("#file_tag_status").html(data.results);
            }
        },
        cache: false
    });
	}
	
	update_status();	

	function get_object_comments () {
    $.ajax({
        url: '/all_object_comments/',
        type: 'get',
        dataType: 'json',
        data: { parent_hash: hash },
        success: function(data) {
            if(data.success == true) {
				for (i=0;i<=data.results.length;i++) {
					ident = "." + data.results[i] + "_img";
					$(ident).attr("src","/media/img/comment.jpg");
				}
            }
        },
        cache: false
    });
	}

	get_object_comments()

    $("#flagged_malicious").click(function(){
        $.ajax({
            url: '/flag_file/',
            type: 'post',
            dataType: 'json',
            data: { hash: hash, tag: "malware"},
            success: function(data) {
                if(data.success == true) {
					update_status();				
                } else {
					alert("error in flagging");
				}
            },
            cache: false
        });
        return false;
    });

    $("#flagged_non-malicious").click(function(){
        $.ajax({
            url: '/flag_file/',
            type: 'post',
            dataType: 'json',
            data: { hash: hash, tag: "non-malicious"},
            success: function(data) {
                if(data.success == true) {
                    update_status();
                } else {
                    alert("error in flagging");
                }
            },
            cache: false
        });
        return false;
    });

});
