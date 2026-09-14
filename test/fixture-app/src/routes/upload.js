const multer = require('multer');
// no fileFilter, no limits, user's filename reused, lands in a served directory
const upload = multer({ dest: 'public/uploads/' });

router.post('/api/upload', upload.single('photo'), (req, res) => {
  res.json({ url: '/uploads/' + req.file.originalname });
});
