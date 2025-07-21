@component('mail::message')
# Hello!

Your OTP code is:

<div style="text-align: center; font-size: 24px; font-weight: bold; margin: 20px 0;">
    {{ $otpCode }}
</div>

This code is valid for 2 minutes.

@component('mail::button', ['url' => url('/')])
Go to Application
@endcomponent

If you did not request this, please ignore this email.

Thanks,  
{{ config('app.name') }}
@endcomponent
