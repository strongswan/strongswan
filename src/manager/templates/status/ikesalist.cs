<?cs include:"templates/header.cs" ?>
<?cs each:ikesa = ikesas ?>
  <div class="expand" id="ikesa-<?cs name:ikesa ?>">
  <h1>
  	<?cs name:ikesa ?> [<?cs var:ikesa.peerconfig ?>]:
  	<span><?cs var:ikesa.local.identification ?></span> &lt;-&gt; 
  	<span><?cs var:ikesa.remote.identification ?></span>
  </h1> 
  <div>
    <hr/>
    <table class="drawing">
      <tr>
        <td>
        </td>
        <td class="left" colspan="2">
          <?cs var:ikesa.local.identification ?>
        </td>
        <td>
        </td>
        <td class="right" colspan="2">
          <?cs var:ikesa.remote.identification ?>
        </td>
        <td>
        </td>
      </tr>
      <tr>
        <td>
        </td>
        <td>
        </td>
        <td class="center" colspan="3">
          <?cs var:ikesa.local.spi ?>:<?cs var:ikesa.remote.spi ?>
        </td>
        <td>
        </td>
        <td>
        </td>
      </tr>
      <tr class="images">
        <td>
		<?cs each:net = ikesa.childsas.local ?>
		  <p><?cs var:net ?></p>
		<?cs /each ?>
        </td>
        <td>
          <?cs if:ikesa.role == "initiator" ?>
          <img title="Local host is the initiator" src="<?cs var:base ?>/static/client-left.png"></img>
          <?cs else ?>
          <img title="Local host is the responder" src="<?cs var:base ?>/static/gateway-left.png"></img>
          <?cs /if ?>
        </td>
        <td>
          <?cs if:ikesa.local.nat == "true" ?>
          <img title="Local host is behind a NAT router" src="<?cs var:base ?>/static/router.png"></img>
          <?cs else ?>
          <img title="Local host is not NATed" src="<?cs var:base ?>/static/pipe.png"></img>
          <?cs /if ?>
        </td>
        <td>
          <?cs if:ikesa.status == "established" ?>
          <img title="IKE connection <?cs var:ikesa.status ?>" src="<?cs var:base ?>/static/pipe-good.png"></img>
          <?cs else ?>
          <img title="IKE connection in state <?cs var:ikesa.status ?>" src="<?cs var:base ?>/static/pipe-bad.png"></img>
          <?cs /if ?>
        </td>
        <td>
          <?cs if:ikesa.remote.nat == "true" ?>
          <img title="Remote host is behind a NAT router" src="<?cs var:base ?>/static/router.png"></img>
          <?cs else ?>
          <img title="Remote host is the responder" src="<?cs var:base ?>/static/pipe.png"></img>
          <?cs /if ?>
        </td>
        <td>
          <?cs if:ikesa.role == "responder" ?>
          <img title="Remote host is the initiator" src="<?cs var:base ?>/static/client-right.png"></img>
          <?cs else ?>
          <img title="Remote host is the responder" src="<?cs var:base ?>/static/gateway-right.png"></img>
          <?cs /if ?>
        </td>
        <td>
		<?cs each:net = ikesa.childsas.remote ?>
		  <p><?cs var:net ?></p>
		<?cs /each ?>
        </td>
      </tr>
      <tr>
        <td>
        </td>
        <td class="left" colspan="2">
          <?cs var:ikesa.local.address ?>:<?cs var:ikesa.local.port ?>
        </td>
        <td>
        </td>
        <td class="right" colspan="2">
          <?cs var:ikesa.remote.address ?>:<?cs var:ikesa.remote.port ?>
        </td>
        <td>
        </td>
      </tr>
    </table>
  </div>
  </div>
<?cs /each ?>
<?cs include:"templates/footer.cs" ?>
