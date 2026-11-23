import unittest
import os
from types import SimpleNamespace
from unittest import mock
from runner.firewall import build_command, main
from app.gui import dispatch


class FirewallTests(unittest.TestCase):
    def test_command_is_disabled_and_normalized(self):
        self.assertEqual(build_command('drop', 'tcp', '0022', '192.168.88.5/24', '123'),
            '/ip firewall filter add chain=input action=drop protocol=tcp dst-port=22 src-address=192.168.88.0/24 disabled=yes comment="github-actions-123"')

    def test_rejects_bad_fields_and_injection(self):
        good = ['drop', 'tcp', '22', '192.168.1.0/24', '123']
        bad_values = ['drop; /system reboot', 'tcp;foo', '22;reboot', '0.0.0.0/0;reboot', '123"']
        for index, value in enumerate(bad_values):
            args = good.copy()
            args[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                build_command(*args)
        for port in ('0', '65536', '-1', '1-2', '１２'):
            with self.subTest(port=port), self.assertRaises(ValueError):
                build_command('drop', 'tcp', port, '1.2.3.4', '1')
        with self.assertRaises(ValueError):
            build_command('drop', 'tcp', '22', '::/0', '1')

    def test_runner_invokes_ssh_and_cleans_key(self):
        env = {'INPUT_ACTION': 'drop', 'INPUT_PROTOCOL': 'tcp', 'INPUT_PORT': '22',
               'INPUT_SOURCE': '192.168.1.0/24', 'GITHUB_RUN_ID': '42',
               'ROUTER_HOST': 'router.example', 'ROUTER_USER': 'operator',
               'ROUTER_SSH_KEY': 'private-key', 'ROUTER_KNOWN_HOSTS': 'pinned-host-key'}
        paths = []
        def fake_run(args, **kwargs):
            key = args[args.index('-i') + 1]
            hosts = next(arg.split('=', 1)[1] for arg in args if arg.startswith('UserKnownHostsFile='))
            paths.extend([key, hosts])
            self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
            with open(key, encoding='utf-8') as f:
                self.assertEqual(f.read(), 'private-key\n')
            self.assertIn('StrictHostKeyChecking=yes', args)
            self.assertIn('disabled=yes', args[-1])
            return SimpleNamespace(returncode=0)
        with mock.patch.dict(os.environ, env, clear=True), mock.patch('runner.firewall.subprocess.run', side_effect=fake_run):
            self.assertEqual(main(), 0)
        self.assertTrue(paths)
        self.assertTrue(all(not os.path.exists(path) for path in paths))

    def test_dispatch_request(self):
        response = mock.MagicMock()
        response.__enter__.return_value.status = 204
        with mock.patch('app.gui.urlopen', return_value=response) as urlopen:
            dispatch('owner/repo', 'main', 'secret', {'port': '22'})
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, 'https://api.github.com/repos/owner/repo/actions/workflows/routeros-firewall.yml/dispatches')
        self.assertIn(b'"ref": "main"', request.data)
        self.assertEqual(request.get_header('Authorization'), 'Bearer secret')

    def test_rejects_bad_repository(self):
        with self.assertRaises(ValueError):
            dispatch('evil/repo/extra', 'main', 'token', {})

if __name__ == '__main__':
    unittest.main()
