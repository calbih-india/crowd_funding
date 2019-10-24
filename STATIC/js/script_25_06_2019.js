$(document).ready(function(){

var nav_offset_top = $('#mainNav').height() + 20; 
    function navbarFixed(){
        if ( $('.header_area').length ){ 
            $(window).scroll(function() {
                var scroll = $(window).scrollTop();   
                if (scroll >= nav_offset_top ) {
                    $(".header_area").addClass("navbar_fixed");
                } else {
                    $(".header_area").removeClass("navbar_fixed");
                }
            });
        };
    };

        navbarFixed();


    $('#user_citizen_id').click(function(){
        if($(this).prop("checked") == true){
          $("#user_citizen_id_text").text("I am an Indian citizen");
            $(this).parent().parent().addClass("jss878 jss877");
        }
        else if($(this).prop("checked") == false){
            $("#user_citizen_id_text").text("I am not an Indian citizen");
          $(this).parent().parent().removeClass("jss878 jss877");
        }
    });


    $('#contact_details_private').click(function(){
        if($(this).prop("checked") == true){
          $("#contact_details_private_text").text("I trust the Campaigner and my contact details can be shared with them.");
            $(this).parent().parent().addClass("jss878 jss877");
        }
        else if($(this).prop("checked") == false){
            $("#contact_details_private_text").text("Keep me updated but keep my contact details private.");
          $(this).parent().parent().removeClass("jss878 jss877");
        }
    });

    
    // Validation Starts Here

    $("#reg_name").keyup(function(){
        if($(this).val().trim() != ""){
            $(this).parent().parent().find(".error").text("");
        }
        else {
            $(this).parent().parent().find(".error").text("Please enter a correct name");
        }
    });

    $("#reg_email").keyup(function(){
        if($(this).val().trim().match(/^([\w-\.]+@([\w-]+\.)+[\w-]{2,6})?$/) == null){
            $(this).parent().parent().find(".error").text("Please enter a correct Email Id and remove any spaces");
        }
        else{
            $(this).parent().parent().find(".error").text("");
        }
    });   
    

    $("#forget_email").keyup(function(){
        if($(this).val().trim().match(/^([\w-\.]+@([\w-]+\.)+[\w-]{2,6})?$/) == null){
            $(this).parent().parent().find(".error").text("Please enter a correct Email Id and remove any spaces");
        }
        else{
            $(this).parent().parent().find(".error").text("");
        }
    });    


    $("#log_email").keyup(function(){
        if($(this).val().trim().match(/^([\w-\.]+@([\w-]+\.)+[\w-]{2,6})?$/) == null){
            $(this).parent().parent().find(".error").text("Please enter a correct Email Id and remove any spaces");
        }
        else{
            $(this).parent().parent().find(".error").text("");
        }
    });   

    $("#reg_pass").keyup(function(){
        if($(this).val().trim() == "" || $(this).val().length < 8){
            $(this).parent().parent().find(".error").text("Should be equal to or more than 8 characters");
        }
        else {
            $(this).parent().parent().find(".error").text("");
        }
    });

    $("#log_pass").keyup(function(){
        if($(this).val().trim() == "" || $(this).val().length < 8){
            $(this).parent().parent().parent().find(".error").text("Should be equal to or more than 8 characters");
        }
        else {
            $(this).parent().parent().parent().find(".error").text("");
        }
    });


    $("#mobile-number").keyup(function(){
        if($(this).val().trim() == ""){
            $(this).parent().parent().parent().find(".error").text("Please enter a correct Mobile No");
        }
        else {
            $(this).parent().parent().parent().find(".error").text("");
        }
    });

    $("#mobile-number").keypress(function(evt){       
        var charCode = (evt.which) ? evt.which : evt.keyCode;
        if (charCode > 31 && (charCode < 48 || charCode > 57)){
            return false;
        }
    });

    
    $(".integer_value").keypress(function(evt){       
        var charCode = (evt.which) ? evt.which : evt.keyCode;
        if (charCode > 31 && (charCode < 48 || charCode > 57)){
            return false;
        }
    });

    $('#termsCheck_box').change(function(){
        if ($('#termsCheck_box').prop("checked")) {
            $(this).parent().parent().addClass('jss883 jss896');
            $('#termsCheck_box').parent().find('.svg_hide').show();           
            $('#termsCheck_box').parent().find('.svg_show').hide();
            $('.terms_error').toast('hide');
        }
        else{
            $(this).parent().parent().removeClass('jss883 jss896');
            $('#termsCheck_box').parent().find('.svg_hide').hide();
            $('#termsCheck_box').parent().find('.svg_show').show(); 
            $('.terms_error').toast('show');
        }
    });


    

    $('#donation_anonymous_checkbox').change(function(){
        if ($('#donation_anonymous_checkbox').prop("checked")) {
            $(this).parent().parent().addClass('jss883 jss896');
            $('#donation_anonymous_checkbox').parent().find('.svg_hide').show();           
            $('#donation_anonymous_checkbox').parent().find('.svg_show').hide();
        }
        else{
            $(this).parent().parent().removeClass('jss883 jss896');
            $('#donation_anonymous_checkbox').parent().find('.svg_hide').hide();           
            $('#donation_anonymous_checkbox').parent().find('.svg_show').show();
        }
    });

    $('#citizen_voluntary').change(function(){
        if ($('#citizen_voluntary').prop("checked")) {
            $(this).parent().parent().addClass('jss883 jss896');
            $('#citizen_voluntary').parent().find('.svg_hide').show();           
            $('#citizen_voluntary').parent().find('.svg_show').hide();
        }
        else{
            $(this).parent().parent().removeClass('jss883 jss896');
            $('#citizen_voluntary').parent().find('.svg_hide').hide();
            $('#citizen_voluntary').parent().find('.svg_show').show(); 
        }
    });

    $('#hide_my_name').change(function(){
        if ($('#hide_my_name').prop("checked")) {
            $(this).parent().parent().addClass('jss883 jss896');
            $('#hide_my_name').parent().find('.svg_hide').show();           
            $('#hide_my_name').parent().find('.svg_show').hide();
        }
        else{
            $(this).parent().parent().removeClass('jss883 jss896');
            $('#hide_my_name').parent().find('.svg_hide').hide();
            $('#hide_my_name').parent().find('.svg_show').show(); 
        }
    });


    

    // Register Script validation
    regg_name=reg_email=reg_pass=reg_number=log_email=log_pass=trem_check=new_pass=con_pass=0;
    $("#register_btn").click(function(){

        if($("#reg_name").val().trim() != ""){
            $("#reg_name").parent().parent().find(".error").text("");
            regg_name = 0;
        }
        else {
            $("#reg_name").parent().parent().find(".error").text("Please enter a correct name");
            regg_name = 1;
        }

        if($("#reg_email").val().trim().match(/^([\w-\.]+@([\w-]+\.)+[\w-]{2,6})?$/) == null || $("#reg_email").val().trim() == ""){
            $("#reg_email").parent().parent().find(".error").text("Please enter a correct Email Id and remove any spaces");
            reg_email = 1;
        }
        else{
            $("#reg_email").parent().parent().find(".error").text("");
            reg_email = 0;
        }

        if($("#reg_pass").val().trim() == "" || $("#reg_pass").val().length < 8){
            $("#reg_pass").parent().parent().find(".error").text("Should be equal to or more than 8 characters");
            reg_pass = 1 ;
        }
        else {
            $("#reg_pass").parent().parent().find(".error").text("");
            reg_pass = 0 ;
        }

        if($("#mobile-number").val().length < 5){
            $("#mobile-number").parent().parent().parent().find(".error").text("Please enter a correct Mobile No");       
            reg_number = 1 ;     
        }
        else {
            $("#mobile-number").parent().parent().parent().find(".error").text("");
            reg_number = 0 ;
        }


        if ($('#termsCheck_box').prop("checked")) {
            // checked
            $('.terms_error').toast('hide');
            // return;
            trem_check = 0
        }
        else{
            // alert("not checked");
            $('.terms_error').toast('show');
            trem_check = 1
        }

        if(reg_number == 1 || reg_email == 1 || reg_pass == 1 || regg_name == 1 || trem_check == 1 ){
            return false
        }

    });

    $("#login_btn").click(function(){
        
        if($("#log_email").val().trim().match(/^([\w-\.]+@([\w-]+\.)+[\w-]{2,6})?$/) == null || $("#log_email").val().trim() == ""){
            $("#log_email").parent().parent().find(".error").text("Please enter a correct Email Id and remove any spaces");
            log_email = 1
        }
        else {
            $("#log_email").parent().parent().find(".error").text("");
            log_email = 0
        }

        if($("#log_pass").val().trim() == "" || $("#log_pass").val().length < 8){
            
            $("#log_pass").parent().parent().parent().find(".error").text("Should be equal to or more than 8 characters");
            log_pass = 1
        }
        else {
            $("#log_pass").parent().parent().parent().find(".error").text("");
            log_pass = 0
        }

        if(log_email == 1 || log_pass == 1 ){
            return false
        }

    });

    $("#forget_btn").click(function(){
        if($("#forget_email").val().trim().match(/^([\w-\.]+@([\w-]+\.)+[\w-]{2,6})?$/) == null || $("#forget_email").val().trim() == ""){
            $("#forget_email").parent().parent().find(".error").text("Please enter a correct Email Id and remove any spaces");
            return false;
        }
        else {
            $("#forget_email").parent().parent().find(".error").text("");
        }

    });


    $("#new_pass").keyup(function(){
        if($(this).val().trim() == "" || $(this).val().length < 8){
            $(this).parent().parent().parent().find(".error").text("Should be equal to or more than 8 characters");
            new_pass = 1 ;
        }
        else {
            $(this).parent().parent().parent().find(".error").text("");
            new_pass = 0 ;
        }
    });

    var old_pass = 0;

    $("#old_pass").keyup(function(){
        if($(this).val().trim() == "" || $(this).val().length < 8){
            $(this).parent().parent().parent().find(".error").text("Should be equal to or more than 8 characters");
            old_pass = 1 ;
        }
        else {
            $(this).parent().parent().parent().find(".error").text("");
            old_pass = 0 ;
        }
    });

    $("#con_pass").keyup(function(){
        if($(this).val().trim() == ""){
            $(this).parent().parent().parent().find(".error").text("Should be equal to or more than 8 characters");
            con_pass = 1 ;
        }
        else {
            if($("#con_pass").val() != $("#new_pass").val()){
                $("#con_pass").parent().parent().parent().find(".error").text("Repeat Password must match with new password");
                con_pass = 1 ;
            }
            else{
                $(this).parent().parent().parent().find(".error").text("");
                con_pass = 0 ;
            }
        }
    });

    $("#new_pass_btn").click(function(){
        if( new_pass == 0  && con_pass == 0) {
            if($("#con_pass").val() != $("#new_pass").val()){
                $("#con_pass").parent().parent().parent().find(".error").text("Repeat Password must match with new password");
                return false;
            }
        }
        else if( new_pass == 0  && con_pass == 1) {
            return false;
        }
    });

    $("#change_pass_btn").click(function(){
        if( new_pass == 0  && con_pass == 0 && old_pass == 0) {
            if($("#con_pass").val() != $("#new_pass").val()){
                $("#con_pass").parent().parent().parent().find(".error").text("Repeat Password must match with new password");
                return false;
            }
        }
        else if( new_pass == 0  && con_pass == 1) {
            return false;
        }
    });


    if ($("#citizen_voluntary").is(':checked')){
        $('#citizen_voluntary').parent().parent().addClass('jss883 jss896');
        $('#citizen_voluntary').find('.svg_hide').show();           
        $('#citizen_voluntary').find('.svg_show').hide();
    }

    if ($("#donation_anonymous_checkbox").is(':checked')){
        $('#donation_anonymous_checkbox').parent().parent().addClass('jss883 jss896');
        $('#citizen_voluntary').parent().find('.svg_hide').show();           
        $('#citizen_voluntary').parent().find('.svg_show').hide();
    }

    


    if ($("#termsCheck_box").is(':checked')){
        $('#termsCheck_box').parent().parent().addClass('jss883 jss896');
        $('#termsCheck_box').parent().find('.svg_hide').show();           
        $('#termsCheck_box').parent().find('.svg_show').hide();
            $('.terms_error').toast('hide');
    }

    

});




var _validFileExtensions_img = [".jpeg", ".jpg",".png"];    
             
function Validateimgupload(oInputimg) {
    if (oInputimg.type == "file") {
                
        var sFileName = oInputimg.value;
        
        if (sFileName.length > 0) {
            var blnValid = false;
            for (var j = 0; j < _validFileExtensions_img.length; j++) {
                var sCurExtension = _validFileExtensions_img[j];
                if (sFileName.substr(sFileName.length - sCurExtension.length, sCurExtension.length).toLowerCase() == sCurExtension.toLowerCase()) {
                    blnValid = true;
                    if (blnValid) {
                      var fsize = $('#id_resume')[0].files[0].size;
                        if (oInputimg.files && oInputimg.files[0]) {
                      var reader = new FileReader();

                        reader.readAsDataURL(oInputimg.files[0]);
                        reader.onload = function (e) {
                            //Initiate the JavaScript Image object.
                            var image = new Image();
             
                            //Set the Base64 string return from FileReader as source.
                            image.src = e.target.result;
                                   
                            $("#img_val").text("");
                    }
                }
            }
                    break;
                }
            }
            if (!blnValid) {

             $("#img_val").text("Allowed file format : (.png/jpg/jpeg)");
                
                oInputimg.value = "";
                return false;
            }
        }
        
         if (blnValid) {
            var fsize = $('#id_resume')[0].files[0].size;
           
            if (oInputimg.files && oInputimg.files[0]) {
                var reader = new FileReader();

                reader.onload = function (e) {
                    $('#blah')
                        .attr('src', e.target.result);                                    
                };

                reader.readAsDataURL(oInputimg.files[0]);
                reader.onload = function (e) {
                    //Initiate the JavaScript Image object.
                    var image = new Image();
     
                    //Set the Base64 string return from FileReader as source.
                    image.src = e.target.result;
                           
                 
     
                }
            }
        }
        
    }
}



$('.count').each(function () {
    $(this).prop('Counter',0).animate({
        Counter: $(this).text()
    }, {
        duration: 4000,
        easing: 'swing',
        step: function (now) {
            $(this).text(Math.ceil(now));
        }
    });
});