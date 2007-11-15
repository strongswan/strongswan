<?cs include:"templates/header.cs" ?>
<?cs each:peercfg = peercfgs ?>
  <div class="expand" id="peercfg-<?cs name:peercfg ?>">
  <h1><?cs name:peercfg ?>:
  	<span><?cs var:peercfg.local ?></span> &lt;-&gt; 
  	<span><?cs var:peercfg.remote ?></span>
  </h1>
  <div class="controls">
    <a title="initiate SA" href="<?cs var:base ?>/control/initiateike/<?cs name:peercfg ?>">
      <img src="<?cs var:base ?>/static/initiate.png"/>
    </a>
  </div>
  <div class="expander">
    <hr/>
    <p><?cs var:peercfg.ikecfg.local ?> - <?cs var:peercfg.ikecfg.remote ?></p>
    <?cs each:childcfg = peercfg.childcfgs ?>
    <div class="expand">
    <h1><?cs name:childcfg ?>:</h1>
	  <div class="controls">
		<a title="initiate SA" href="<?cs var:base ?>/control/initiatechild/<?cs name:childcfg ?>">
		  <img src="<?cs var:base ?>/static/initiate.png"/>
		</a>
	  </div>
    <div class="expander">
    <table>
      <tr class="images">
      	<td>
          <?cs each:net = childcfg.local.networks ?>
      	    <p><?cs var:net ?></p>
          <?cs /each ?>
      	</td>
      	<td>&lt;-&gt;</td>
      	<td class="right">
          <?cs each:net = childcfg.remote.networks ?>
      	    <p><?cs var:net ?></p>
          <?cs /each ?>
      	</td>
      </tr>
    </table>
	</div>
	</div>
    <?cs /each ?>
  </div>
  </div>
<?cs /each ?>
<?cs include:"templates/footer.cs" ?>
