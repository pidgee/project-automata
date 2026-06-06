from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import mysql.connector
import ldap
import ansible_runner
import os
import tempfile

app = Flask(__name__)
app.secret_key = 'proyecto_instituto_2024_secretkey'

db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': 'abc123.',
    'database': 'inventario_db'
}

LDAP_SERVER = 'ldap://10.0.0.2'
LDAP_DOMAIN = 'proyecto.local'
LDAP_OU_PROFESORES = 'OU=Profesores,OU=Usuarios,DC=proyecto,DC=local'
WINDOWS_USER = 'Administrador'
WINDOWS_PASS = 'abc123.'
LINUX_USER = 'usuario'
LINUX_KEY = '/root/.ssh/id_rsa'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Debes iniciar sesion para acceder.'

class User(UserMixin):
    def __init__(self, username, display_name):
        self.id = username
        self.display_name = display_name

@login_manager.user_loader
def load_user(user_id):
    return User(user_id, user_id)

def autenticar_ldap(username, password):
    try:
        conn = ldap.initialize(LDAP_SERVER)
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
        user_dn = f"{username}@{LDAP_DOMAIN}"
        conn.simple_bind_s(user_dn, password)
        resultado = conn.search_s(LDAP_OU_PROFESORES, ldap.SCOPE_SUBTREE, f'(sAMAccountName={username})', ['displayName'])
        if resultado:
            attrs = resultado[0][1]
            display_name = attrs.get('displayName', [username.encode()])[0]
            if isinstance(display_name, bytes):
                display_name = display_name.decode('utf-8')
            conn.unbind_s()
            return True, display_name
        conn.unbind_s()
        return False, 'Usuario no pertenece a la OU de Profesores'
    except ldap.INVALID_CREDENTIALS:
        return False, 'Credenciales incorrectas'
    except ldap.SERVER_DOWN:
        return False, 'No se puede conectar al servidor AD'
    except Exception as e:
        return False, str(e)

def get_db():
    return mysql.connector.connect(**db_config)

def get_equipo(id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM equipos WHERE id=%s", (id,))
    equipo = cursor.fetchone()
    cursor.close()
    conn.close()
    return equipo

def es_windows(os_str):
    return 'windows' in os_str.lower() or 'win' in os_str.lower()

def run_playbook(ip, os_str, playbook_content):
    es_win = es_windows(os_str)
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(f"{tmpdir}/project", exist_ok=True)
        os.makedirs(f"{tmpdir}/inventory", exist_ok=True)
        if es_win:
            inventory = f"[target]\n{ip} ansible_user={WINDOWS_USER} ansible_password={WINDOWS_PASS} ansible_connection=winrm ansible_winrm_transport=ntlm ansible_port=5985 ansible_winrm_server_cert_validation=ignore\n"
        else:
            inventory = f"[target]\n{ip} ansible_user={LINUX_USER} ansible_ssh_private_key_file={LINUX_KEY} ansible_become=yes ansible_become_method=sudo\n"
        with open(f"{tmpdir}/inventory/hosts", 'w') as f:
            f.write(inventory)
        with open(f"{tmpdir}/project/playbook.yml", 'w') as f:
            f.write(playbook_content)
        result = ansible_runner.run(private_data_dir=tmpdir, playbook='playbook.yml', quiet=True)
        return result.status == 'successful'

def pb_reiniciar(es_win):
    if es_win:
        return "---\n- hosts: target\n  tasks:\n    - name: Reiniciar\n      ansible.windows.win_reboot:\n"
    return "---\n- hosts: target\n  become: yes\n  tasks:\n    - name: Reiniciar\n      reboot:\n"

def pb_apagar(es_win):
    if es_win:
        return "---\n- hosts: target\n  tasks:\n    - name: Apagar\n      ansible.windows.win_shell: Stop-Computer -Force\n"
    return "---\n- hosts: target\n  become: yes\n  tasks:\n    - name: Apagar\n      shell: shutdown -h now\n"

def pb_hostname(es_win, nombre):
    if es_win:
        return f"---\n- hosts: target\n  tasks:\n    - name: Hostname\n      ansible.windows.win_hostname:\n        name: {nombre}\n    - name: Reiniciar\n      ansible.windows.win_reboot:\n"
    return f"---\n- hosts: target\n  become: yes\n  tasks:\n    - name: Hostname\n      hostname:\n        name: {nombre}\n"

def pb_ip(es_win, ip, mascara, gw):
    if es_win:
        return f"---\n- hosts: target\n  tasks:\n    - name: IP\n      ansible.windows.win_shell: |\n        $a = Get-NetAdapter | Where-Object {{$_.Status -eq 'Up'}} | Select-Object -First 1\n        Remove-NetIPAddress -InterfaceIndex $a.ifIndex -Confirm:$false -ErrorAction SilentlyContinue\n        New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress {ip} -PrefixLength {mascara} -DefaultGateway {gw}\n"
    return f"---\n- hosts: target\n  become: yes\n  tasks:\n    - name: IP\n      shell: |\n        IFACE=$(ip route | grep default | awk '{{print $5}}' | head -1)\n        ip addr flush dev $IFACE\n        ip addr add {ip}/{mascara} dev $IFACE\n        ip route add default via {gw}\n"

@app.route('/')
def home():
    return redirect(url_for('inventario') if current_user.is_authenticated else url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('inventario'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            error = 'Introduce usuario y contrasena.'
        else:
            ok, result = autenticar_ldap(username, password)
            if ok:
                login_user(User(username, result))
                return redirect(url_for('inventario'))
            else:
                error = result
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/inventario')
@login_required
def inventario():
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM equipos ORDER BY fecha DESC")
        equipos = cursor.fetchall()
        cursor.close()
        conn.close()
        return render_template('inventario.html', equipos=equipos)
    except Exception as e:
        return render_template('inventario.html', equipos=[], error=str(e))

@app.route('/equipo/<int:id>')
@login_required
def detalle_equipo(id):
    equipo = get_equipo(id)
    if not equipo:
        flash('Equipo no encontrado.', 'danger')
        return redirect(url_for('inventario'))
    return render_template('detalle.html', equipo=equipo)

@app.route('/equipo/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_equipo(id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    if request.method == 'POST':
        cursor.execute("UPDATE equipos SET hostname=%s, ip=%s, os=%s, status=%s WHERE id=%s",
            (request.form['hostname'], request.form['ip'], request.form['os'], request.form['status'], id))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Equipo actualizado.', 'success')
        return redirect(url_for('detalle_equipo', id=id))
    cursor.execute("SELECT * FROM equipos WHERE id=%s", (id,))
    equipo = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('editar.html', equipo=equipo)

@app.route('/equipo/<int:id>/baja', methods=['POST'])
@login_required
def dar_baja(id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE equipos SET status='baja' WHERE id=%s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Equipo dado de baja.', 'warning')
    return redirect(url_for('inventario'))

@app.route('/equipo/<int:id>/eliminar', methods=['POST'])
@login_required
def eliminar_equipo(id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM equipos WHERE id=%s", (id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash('Equipo eliminado.', 'danger')
    return redirect(url_for('inventario'))

@app.route('/equipo/<int:id>/reiniciar', methods=['POST'])
@login_required
def reiniciar_equipo(id):
    equipo = get_equipo(id)
    ok = run_playbook(equipo['ip'], equipo['os'], pb_reiniciar(es_windows(equipo['os'])))
    flash(f'Equipo {equipo["hostname"]} reiniciado.' if ok else 'Error al reiniciar.', 'success' if ok else 'danger')
    return redirect(url_for('detalle_equipo', id=id))

@app.route('/equipo/<int:id>/apagar', methods=['POST'])
@login_required
def apagar_equipo(id):
    equipo = get_equipo(id)
    ok = run_playbook(equipo['ip'], equipo['os'], pb_apagar(es_windows(equipo['os'])))
    if ok:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE equipos SET status='offline' WHERE id=%s", (id,))
        conn.commit()
        cursor.close()
        conn.close()
    flash(f'Equipo {equipo["hostname"]} apagado.' if ok else 'Error al apagar.', 'success' if ok else 'danger')
    return redirect(url_for('detalle_equipo', id=id))

@app.route('/equipo/<int:id>/cambiar_hostname', methods=['POST'])
@login_required
def cambiar_hostname(id):
    equipo = get_equipo(id)
    nuevo = request.form['nuevo_hostname']
    ok = run_playbook(equipo['ip'], equipo['os'], pb_hostname(es_windows(equipo['os']), nuevo))
    if ok:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE equipos SET hostname=%s WHERE id=%s", (nuevo, id))
        conn.commit()
        cursor.close()
        conn.close()
    flash(f'Hostname cambiado a {nuevo}.' if ok else 'Error al cambiar hostname.', 'success' if ok else 'danger')
    return redirect(url_for('detalle_equipo', id=id))

@app.route('/equipo/<int:id>/cambiar_ip', methods=['POST'])
@login_required
def cambiar_ip(id):
    equipo = get_equipo(id)
    nueva_ip = request.form['nueva_ip']
    mascara = request.form.get('mascara', '24')
    gateway = request.form.get('gateway', '10.0.0.1')
    ok = run_playbook(equipo['ip'], equipo['os'], pb_ip(es_windows(equipo['os']), nueva_ip, mascara, gateway))
    if ok:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("UPDATE equipos SET ip=%s WHERE id=%s", (nueva_ip, id))
        conn.commit()
        cursor.close()
        conn.close()
    flash(f'IP cambiada a {nueva_ip}.' if ok else 'Error al cambiar IP.', 'success' if ok else 'danger')
    return redirect(url_for('detalle_equipo', id=id))

@app.route('/registrar', methods=['POST'])
def registrar():
    data = request.json
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""INSERT INTO equipos (hostname, ip, os, status)
                   VALUES (%s,%s,%s,%s)
                   ON DUPLICATE KEY UPDATE status=%s, fecha=NOW()""",
            (data['hostname'], data['ip'], data['os'], data['status'], data['status']))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"mensaje": "Registro exitoso"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/equipo/<int:id>/actualizar', methods=['POST'])
@login_required
def actualizar_equipo(id):
    equipo = get_equipo(id)
    if es_windows(equipo['os']):
        flash('Actualización solo disponible para Linux.', 'warning')
        return redirect(url_for('detalle_equipo', id=id))

    playbook = """---
- hosts: target
  become: yes
  tasks:
    - name: apt update
      apt:
        update_cache: yes
      register: update_result

    - name: apt upgrade
      apt:
        upgrade: dist
      register: upgrade_result

    - name: Mostrar paquetes actualizados
      debug:
        msg: "{{ upgrade_result.stdout_lines }}"
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(f"{tmpdir}/project", exist_ok=True)
        os.makedirs(f"{tmpdir}/inventory", exist_ok=True)
        inventory = f"[target]\n{equipo['ip']} ansible_user={LINUX_USER} ansible_ssh_private_key_file={LINUX_KEY} ansible_become=yes ansible_become_method=sudo\n"
        with open(f"{tmpdir}/inventory/hosts", 'w') as f:
            f.write(inventory)
        with open(f"{tmpdir}/project/playbook.yml", 'w') as f:
            f.write(playbook)
        result = ansible_runner.run(private_data_dir=tmpdir, playbook='playbook.yml', quiet=False)
        ok = result.status == 'successful'
        log_lines = []
        for event in result.events:
            if event.get('event') == 'runner_on_ok':
                res = event.get('event_data', {}).get('res', {})
                stdout = res.get('stdout', '')
                if stdout:
                    log_lines.append(stdout)

    if ok:
        log = '\n'.join(log_lines) if log_lines else 'Sistema ya actualizado, no había paquetes pendientes.'
        flash(f'Actualización completada:\n{log}', 'success')
    else:
        flash('Error durante la actualización.', 'danger')

    return redirect(url_for('detalle_equipo', id=id))
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
