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
    $.ajax({
		url: '/file_status/',
        type: 'post',
        dataType: 'json',
        data: { hash: hash },
        success: function(data) {
        	if(data.success == true) {
                
			}
        },
       	cache: false
    });


    $(".flag").click(function(){
	    $.ajax({
		    url: '/flag/',
		    type: 'post',
		    dataType: 'json',
		    data: { hash: this.name },
		    success: function(data) {
			    if(data.success == true) {
				    alert("updated " + data.results);
			    }
		    },
		    cache: false
	    });
	    return false;
    });
    
    $(".skip").click(function(){
	    $.ajax({
		    url: '/skip/',
		    type: 'post',
		    dataType: 'json',
		    data: { hash: this.name },
		    success: function(data) {
			    if(data.success == true) {
				    alert("skipped  " + data.results);
			    }
		    },
		    cache: false
	    });
	    return false;
	});
});

