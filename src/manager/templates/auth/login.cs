<?cs include:"templates/header.cs" ?>
<form method="post" action="<?cs var:action ?>">
  <table width="100%">
    <tr>
      <td>Username</td><td><input type="text" name="username" value="" size="25" /></td>
    </tr>
    <tr>
      <td>Password</td><td><input type="password" name="password" value="" size="25" /></td>
    </tr>
    <tr>
      <td/><td><input type="submit" value="Login"/></td>
    </tr>
</table>
</form>
<?cs include:"templates/footer.cs" ?>
