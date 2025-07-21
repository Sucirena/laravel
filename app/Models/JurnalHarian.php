<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

class JurnalHarian extends Model
{
    use HasFactory;
    
        protected $table = 'jurnal_harian';

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'id_pasien',
        'judul',
        'isi',
        'nilai_emosi',
    ];

    /**
     * Boot the model and add the UUID creation event.
     */
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            if (empty($model->{$model->getKeyName()})) {
                $model->{$model->getKeyName()} = (string) Str::uuid();
            }
        });
    }

    /**
     * Get the pasien that owns the jurnal_harian.
     */
    public function pasien()
    {
        return $this->belongsTo(Pasien::class, 'id_pasien');
    }
}
