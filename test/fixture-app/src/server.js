const cors = require('cors');
app.use(cors({ origin: '*', credentials: true }));

// No authentication check on any of these.
app.get('/api/users/:id', (req, res) => res.json(getUser(req.params.id)));
app.get('/api/orders', (req, res) => res.json(allOrders()));
app.post('/api/admin/delete-user', (req, res) => deleteUser(req.body.id));
app.get('/api/reports', (req, res) => res.json(reports()));
app.post('/api/settings', (req, res) => saveSettings(req.body));
