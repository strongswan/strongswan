
$(function(){
  $(".expand > div").hide();
  $(".expand > h1").toggle(
    function(){$(this).parent(".expand").find("div").slideDown('fast');},
    function(){$(this).parent(".expand").find("div").slideUp('fast');}
  );
});
