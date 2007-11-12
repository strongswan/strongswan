
$(function(){
  $(".expander").hide();
  $(".expand > h1").toggle(
    function(){$(this).parent(".expand").find(".expander").slideDown('fast');},
    function(){$(this).parent(".expand").find(".expander").slideUp('fast');}
  );
});
