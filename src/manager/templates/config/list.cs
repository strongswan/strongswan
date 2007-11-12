<?cs include:"templates/header.cs" ?>
<?cs each:peercfg = peercfgs ?>
  <div class="expand" id="peercfg-<?cs name:peercfg ?>">
  <h1><?cs name:peercfg ?></h1>
  <div class="controls">
    <a title="initiate SA" href="<?cs var:base ?>/control/initiate/<?cs name:peercfg ?>">
      <img src="<?cs var:base ?>/static/initiate.png"/>
    </a>
  </div>
  <div class="expander">
    <hr/>
    <?cs var:peercfg.local ?> - <?cs var:peercfg.remote ?>
    <hr/>
    <?cs each:childcfg = peercfg.childcfgs ?>
    helo
    <table>
      <tr>
        <td colspan="2"><?cs name:childcfg ?></td>
      </tr>
      <tr>
      	<td>Local</td>
      	<td>Remote</td>
      </tr>
      <tr>
        <td>
		  <?cs each:net = childcfg.local.networks ?>
	  	    <p><?cs var:net ?></p>
		  <?cs /each ?>
		</td>
        <td>
		  <?cs each:net = childcfg.remote.networks ?>
	  	    <p><?cs var:net ?></p>
		  <?cs /each ?>
		</td>
	  </tr>
	</table>
    <?cs /each ?>
  </div>
  </div>
<?cs /each ?>
<?cs include:"templates/footer.cs" ?>
