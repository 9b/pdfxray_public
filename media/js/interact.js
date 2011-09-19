var object_comment_content;

function onImgError(source) {
	source.src = "/media/previews/none.png";
	source.onerror = "";
	return true;
}

function html_encode(s)
{
  var el = document.createElement("div");
  el.innerText = el.textContent = s;
  s = el.innerHTML;
  delete el;
  return s;
}

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


	$(".toggle_container").hide();
	 
	$("h2.trigger").click(function(){
		$(this).toggleClass("active").siblings(".toggle_container").slideToggle("slow");
		return false;
	});
	
	$("h2#smobj").click(function(){
		fill_objects(this);
	});
	
	$("h2#lgobj").click(function(){
		fill_objects(this);
	});
	
	$(".details").hide();
	$("h3.trigger").click(function(){
		$(this).toggleClass("active").next().slideToggle("slow");
		return false;
	});

	$("h4.trigger").click(function(){
		$(this).toggleClass("active").next().slideToggle("slow");
		return false;
	});
	
	$("#submit").click(function () {
		$("#loading").toggle();
		$("#upload_form").toggle();
		$("#search_form").toggle();
	});
	
	$(".show_more_data").click(function () {
		$(".more_data").show();
		$(".show_more_data").hide()
		return false;
	});
	
	$("#full_sample_help").click(function () {
		$('#help_dialog').html("<h2>PDF X-RAY filters your uploaded sample to only show the most useful information when trying to identify if your sample is malicious. However, there are times when you need the full PDF to make a final judgement. Going to the full sample will provide all of the PDF objects along with more details about the PDF.</h2>");
		$('#help_dialog').dialog({
			resizable: false,
			title: "<h2>Full Sample Help</h2>",
			height:300,
			width:400,
			modal: true,
			buttons: {
				Ok: function() {
					$( this ).dialog( "close" );
				}
			}
		});
		return false;
	});
	
	$("#general_help").click(function () {
		$('#help_dialog').html("<h2>General Data includes file hashes, PDF header version and filesize. It is generally accepted to categorize samples based on hash, so the information is useful when identifying if your sample is new.</h2>");
		$('#help_dialog').dialog({
			resizable: false,
			title: "<h2>General Data Help</h2>",
			height:300,
			width:400,
			modal: true,
			buttons: {
				Ok: function() {
					$( this ).dialog( "close" );
				}
			}
		});
		return false;
	});
	
	$("#related_malware_help").click(function () {
		$('#help_dialog').html("<h2>It is common for malicious PDF files to be generated from an exploit pack. In some cases these packs generate or use similiar code when creating the malicious PDF. PDF X-RAY compared your uploaded sample to thousands of malicious PDF files looking for any similiar PDF objects.<br><br>If any object matches one of your objects then it will be listed below with a link to the malicious sample and an object reference. Keep in mind that even if your object is related, it does not mean it is malicious. Manual verification is still advised before labeling a PDF as malicious.</h2>");
		$('#help_dialog').dialog({
			resizable: false,
			title: "<h2>Related Malware Help</h2>",
			height:300,
			width:400,
			modal: true,
			buttons: {
				Ok: function() {
					$( this ).dialog( "close" );
				}
			}
		});
		return false;
	});
	
	$("#scans_help").click(function () {
		$('#help_dialog').html("<h2>Anti-virus products are great, but are not terribly helpful when scanning PDFs. It is hard to define a signature to identify a malicious PDF, so more often than not, an anti-virus can be easily fooled. <br><br>However, there are some cases when an anti-virus will point out suspicious material and that is helpful to know when analyzing a PDF. PDF X-RAY pulls this data into the interface so you can see everything in one spot.</h2>");
		$('#help_dialog').dialog({
			resizable: false,
			title: "<h2>Scan Help</h2>",
			height:300,
			width:400,
			modal: true,
			buttons: {
				Ok: function() {
					$( this ).dialog( "close" );
				}
			}
		});
		return false;
	});
	
	$("#suspicious_named_functions_help").click(function () {
		$('#help_dialog').html("<h2>Named functions are called within a PDF document. These functions perform specific functions within a PDF and in a lot of cases, aid in the exploitation of a user. PDF X-RAY locates named function calls associated with malicious files and the exploits they use.</h2>");
		$('#help_dialog').dialog({
			resizable: false,
			title: "<h2>Suspicious Named Functions Help</h2>",
			height:300,
			width:400,
			modal: true,
			buttons: {
				Ok: function() {
					$( this ).dialog( "close" );
				}
			}
		});
		return false;
	});
	
	$("#suspicious_object_help").click(function () {
		$('#help_dialog').html("<h2>When analyzing your PDF, PDF X-RAY will identify suspicious objects based on signatures and known exploits. This helps reduce the amount of objects you need to look for and often finds the exploit if the PDF is malicious.</h2>");
		$('#help_dialog').dialog({
			resizable: false,
			title: "<h2>Suspicious Object Help</h2>",
			height:300,
			width:400,
			modal: true,
			buttons: {
				Ok: function() {
					$( this ).dialog( "close" );
				}
			}
		});
		return false;
	});
	
	$("#large_object_help").click(function () {
		$('#help_dialog').html("<h2>9b+ has done research that shows that exploits are typically located in large PDF objects (over 650 bytes). This is not always the case, but if the file is malicious, it is likely to have the exploit or malicious content in a larger object.</h2>");
		$('#help_dialog').dialog({
			resizable: false,
			title: "<h2>Large Object Help</h2>",
			height:300,
			width:400,
			modal: true,
			buttons: {
				Ok: function() {
					$( this ).dialog( "close" );
				}
			}
		});
		return false;
	});
	
    $("#malicious.flagger").click(function(){
	    $.ajax({
		    url: '/flag/',
		    type: 'post',
		    dataType: 'json',
		    data: { hash: this.name, malicious: true },
		    success: function(data) {
			    if(data.success == true) {
				    $("#non_malicious.flagger").hide()
				    $("#malicious.flagger").html("you flagged this as malicious")
			    }
		    },
		    cache: false
	    });
	    return false;
    });
    
    $("#non_malicious.flagger").click(function(){
	    $.ajax({
		    url: '/flag/',
		    type: 'post',
		    dataType: 'json',
		    data: { hash: this.name, malicious: false },
		    success: function(data) {
			    if(data.success == true) {
				    $("#non_malicious.flagger").html("you flagged this as non-malicious")
				    $("#malicious.flagger").hide()
			    }
		    },
		    cache: false
	    });
	    return false;
    });

    
    $(".related_object_entry").click(function(){
    	    $.ajax({
		    url: '/compare_detail/',
		    type: 'get',
		    dataType: 'json',
		    data: { object_relation: this.id },
		    success: function(data) {
			if (data.success == true) {
				$('#help_dialog').html("<table border='1'><tr><th>Uploaded Sample</th><th>Malicious Sample</th></tr><tr><td width='50%'><p>" + html_encode(data.uploaded_content) + "</p></td><td width='50%'><p>" + html_encode(data.malicious_content) + "</p></td></tr></table>");
				$('#help_dialog').dialog({
					resizable: false,
					title: "<h2>Related Malware Compare</h2>",
					height:500,
					width:800,
					modal: true,
					buttons: {
						Ok: function() {
							$( this ).dialog( "close" );
						}
					}
				});
				return false;
			}
		    },
		    cache: false
	    });
	    return false;
    });

    $(".add_analysis").click(function () {
		var hashes = $(this).attr("name");
		var hashes = hashes.split("_");
		var raw_hash = hashes[0];
		var parent_hash = hashes[1];
		$.ajax({
			url: '/get_object_comment/',
			type: 'get',
			dataType: 'json',
			data: { raw_hash: raw_hash },
			success: function(data) {
				if (data.success == true) {
					object_comment_content = data.results;
					object_form = '<textarea id="analyst_notes">' + object_comment_content + '</textarea>';
        			$('#help_dialog').html(object_form);
        			$('#help_dialog').dialog({
            			resizable: false,
            			title: "<h2>Analyst Notes</h2>",
            			height:500,
            			width:600,
            			modal: true,
            			buttons: {
                			Save: function() {
                               	ident = "." + raw_hash + "_img";
                                $(ident).attr("src","/media/img/ajax-loader.gif");
	                   			analyst_notes = $("#analyst_notes").val();
                    			$.ajax({
                        			url: '/add_object_comment/',
                        			type: 'post',
                        			dataType: 'json',
                        			data: { raw_hash: raw_hash, notes: analyst_notes, parent_hash: parent_hash },
                       				success: function(data) {
                            			if (data.success == true) {
                                			ident = "." + raw_hash + "_img";
                                			$(ident).attr("src","/media/img/comment.jpg");
						     			} else {
                                			alert("Saving analyst notes failed");
                                            ident = "." + raw_hash + "_img";
                                            $(ident).attr("src","/media/img/comment.jpg");                            	
										}
                        			}
                    			});
								$( this ).dialog( "close" );
                			},
                			Close: function() {
                    			object_comment_content = '';                                                             
                    			$( this ).dialog( "close" );
                			}
            			}
        			});
        			return false;
		
				} else {
					object_form = '<textarea id="analyst_notes"></textarea>';
                    $('#help_dialog').html(object_form);
                    $('#help_dialog').dialog({
                        resizable: false,
                        title: "<h2>Analyst Notes</h2>",
                        height:500,
                        width:600,
                        modal: true,
                        buttons: {
                            Save: function() {
                                ident = "." + raw_hash + "_img";
                                $(ident).attr("src","/media/img/ajax-loader.gif");	
                                analyst_notes = $("#analyst_notes").val();
                                $.ajax({
                                    url: '/add_object_comment/',
                                    type: 'post',
                                    dataType: 'json',
                                    data: { raw_hash: raw_hash, notes: analyst_notes, parent_hash: parent_hash },
                                    success: function(data) {
                                        if (data.success == true) {
                                            ident = "." + raw_hash + "_img";
                                            $(ident).attr("src","/media/img/comment.jpg");
                    						$( this ).dialog( "close" ); 
					                   } else {
                                            alert("Saving analyst notes failed");
                                            ident = "." + raw_hash + "_img";
                                            $(ident).attr("src","/media/img/comment.jpg");

                                        }
                                    }
                                });
								$( this ).dialog( "close" );
                            },
                            Close: function() {
                                object_comment_content = '';
                                $( this ).dialog( "close" );
                            }
						}
                    });  
                    return false;
				}
			}
		});
		return false;
    });
	
});

