<?cs include:"templates/header.cs" ?>
<h1>List of IKE SA's</h1>
<table>
  <tr>
    <td>ID</td>
    <td>Status</td>
    <td>Role</td>
    <td>Config</td>
    <td colspan="3">Local</td>
    <td colspan="3">Remote</td>
  <tr>
  <tr>
    <td colspan="4"></td>
    <td>ID</td>
    <td>Address</td>
    <td>SPI</td>
    <td>ID</td>
    <td>Address</td>
    <td>SPI</td>
  <tr>
  <?cs each:ikesa = ikesas ?>
    <td><?cs name:ikesa ?></td>
    <td><?cs var:ikesa.status ?></td>
    <td><?cs var:ikesa.role ?></td>
    <td><?cs var:ikesa.peerconfig ?></td>
    <td><?cs var:ikesa.local.identification ?></td>
    <td><?cs var:ikesa.local.address ?>:<?cs var:ikesa.local.port ?></td>
    <td><?cs var:ikesa.local.spi ?></td>
    <td><?cs var:ikesa.remote.identification ?></td>
    <td><?cs var:ikesa.remote.address ?>:<?cs var:ikesa.remote.port ?></td>
    <td><?cs var:ikesa.remote.spi ?></td>
  <?cs /each ?>
  </tr>
</table>
<?cs include:"templates/footer.cs" ?>
