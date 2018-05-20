from invoke import task

@task
def test(ctx):
    ctx.run('pytest')
    ctx.run('flake8 sslyze')
    ctx.run('mypy sslyze')
