$.get("/user", function (data) {
    $("#user").html(data.name);
    $(".unauthenticated").hide()
    $(".authenticated").show()
});
let logout = function () {
    $.post("/logout", function () {
        $("#user").html('');
        $(".unauthenticated").show();
        $(".authenticated").hide();
    })
    return true;
};
$.get("/error", function (data) {
    if (data) {
        $(".error").html(data);
    } else {
        $(".error").html('');
    }
});
$.ajaxSetup({
    beforeSend: function (xhr, settings) {
        if (settings.type === 'POST'
            || settings.type === 'PUT'
            || settings.type === 'DELETE') {
            if (!(/^http:.*/.test(settings.url) || /^https:.*/
                .test(settings.url))) {
                // Only send the token to relative URLs i.e. locally.
                xhr.setRequestHeader("X-XSRF-TOKEN",
                    Cookies.get('XSRF-TOKEN'));
            }
        }
    }
});